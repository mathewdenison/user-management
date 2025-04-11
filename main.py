import os
import json
import logging
from datetime import datetime, timedelta, date
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
import pkg_resources
from sqlmodel import select

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

from user_management_common_timesheet_mfdenison_hopkinsep.models import Employee, RoleEnum, EmployeeSerializer
from user_management_common_timesheet_mfdenison_hopkinsep.database import get_session
from user_management_common_timesheet_mfdenison_hopkinsep.utils import send_message_to_topic

import google.cloud.logging


client = google.cloud.logging.Client()
client.setup_logging()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://main.d2ue7g6a4mt1cl.amplifyapp.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Setup Templates (for login HTML)
# ----------------------------
templates_path = pkg_resources.resource_filename("user_management_common_timesheet_mfdenison_hopkinsep", "templates")
templates = Jinja2Templates(directory=templates_path)

# ----------------------------
# JWT Authentication Setup
# ----------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key")  # In production, use a strong secret.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def authenticate_employee(username: str, password: str) -> Optional[Employee]:
    """
    Query the database for the Employee with the given username and verify the password.
    """
    session = get_session()
    employee = session.exec(select(Employee).where(Employee.username == username)).first()
    if not employee:
        logger.info(f"No employee found with username '{username}'.")
        return None
    if not pwd_context.verify(password, employee.hashed_password):
        logger.info(f"Password verification failed for username '{username}'.")
        return None
    return employee

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Employee:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    session = get_session()
    employee = session.exec(select(Employee).where(Employee.username == username)).first()
    if employee is None:
        raise credentials_exception
    return employee

async def is_manager_or_hr(user: Employee = Depends(get_current_user)) -> Employee:
    if user.role not in [RoleEnum.Manager, RoleEnum.HR]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    return user

# ----------------------------
# Endpoints
# ----------------------------

# Serve the login form HTML template.
@app.get("/login/", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Login endpoint: verifies username/password against the Employee model and returns a JWT token.
@app.post("/login/")
async def login_view(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    logger.info(f"Received login request for username: {username}")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required.")
    employee = authenticate_employee(username, password)
    if employee:
        access_token = create_access_token(data={"sub": employee.username})
        response_data = {
            "message": f"You are logged in as {username}",
            "role": employee.role,
            "employee_id": employee.id,
            "auth_token": access_token,
            "csrf_token": "dummy-csrf-token"  # Typically not needed with JWT.
        }
        return JSONResponse(response_data)
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/logout/")
async def logout_view():
    return JSONResponse({"message": "You have been logged out successfully."})

# Employee List View (restricted to Managers or HR)
@app.get("/employees/")
async def employee_list(user: Employee = Depends(is_manager_or_hr)):
    session = get_session()
    if user.role == RoleEnum.HR:
        employees = session.exec(select(Employee)).all()
    elif user.role == RoleEnum.Manager:
        if not user.department:
            raise HTTPException(status_code=400, detail="User department information is missing.")
        employees = session.exec(select(Employee).where(Employee.department == user.department)).all()
    else:
        raise HTTPException(status_code=403, detail="Access denied: insufficient permissions.")
    serialized_employees = [EmployeeSerializer.from_orm(emp).dict() for emp in employees]
    return JSONResponse({"employees": serialized_employees})

# Submit TimeLog (employee submits a timesheet)
@app.post("/employees/{employee_id}/submit_timesheet/")
async def submit_timelog(employee_id: int, request: Request, user: Employee = Depends(get_current_user)):
    # Ensure that the signed-in employee matches the employee_id provided in the URL.
    if employee_id != user.id:
        raise HTTPException(status_code=403, detail="You can only submit a timesheet for your own account.")
    data = await request.json()
    message_body = {
        "employee": user.username,  # Enforce that the employee is the authenticated user.
        "week_start_date": data.get("week_start_date"),
        "week_end_date": data.get("week_end_date"),
        "monday_hours": data.get("monday_hours"),
        "tuesday_hours": data.get("tuesday_hours"),
        "wednesday_hours": data.get("wednesday_hours"),
        "thursday_hours": data.get("thursday_hours"),
        "friday_hours": data.get("friday_hours"),
        "pto_hours": data.get("pto_hours")
    }
    message_id = send_message_to_topic('timelog-processing-queue', json.dumps(message_body), 'POST')
    return JSONResponse({"message": "Time log sent for processing.", "message_id": message_id})

# Get TimeLog for an employee.
@app.get("/employees/{employee_id}/get_timesheet/")
async def get_timelog(employee_id: int, user: Employee = Depends(get_current_user)):
    # If the signed-in user is neither HR nor Manager, they can only request their own timesheet.
    if user.role not in [RoleEnum.HR, RoleEnum.Manager] and user.id != employee_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You are not authorized to view other employees' timesheets.")
    queue_data = {"employee_id": employee_id}
    message_id = send_message_to_topic('timelog_list_queue', json.dumps(queue_data), 'GET')
    return JSONResponse({"message": "Time log retrieval request sent.", "message_id": message_id})

# Retrieve Employee TimeLogs for current user.
@app.get("/employees/timelogs/")
async def employee_timelogs(user: Employee = Depends(get_current_user)):
    session = get_session()
    if user.role == RoleEnum.HR:
        employee_ids = session.exec(select(Employee.id)).all()
    elif user.role == RoleEnum.Manager:
        subordinate_ids = [sub.id for sub in user.subordinates] if user.subordinates else []
        employee_ids = [user.id] + subordinate_ids
    else:
        employee_ids = [user.id]
    queue_data = {"role": user.role, "employee_ids": employee_ids}
    message_id = send_message_to_topic('employee_timelog_list_queue', json.dumps(queue_data), 'GET')
    return JSONResponse({"message": "Time log list request sent.", "message_id": message_id})

# Update PTO View (restricted to HR only)
@app.patch("/employees/{employee_id}/pto/")
async def update_pto(employee_id: int, request: Request, user: Employee = Depends(get_current_user)):
    if user.role != RoleEnum.HR:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only HR can update PTO balance.")
    data = await request.json()
    new_balance = data.get("pto_balance")
    if new_balance is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="PTO balance is required.")
    queue_data = {"employee_id": employee_id, "new_balance": new_balance}
    message_id = send_message_to_topic('pto_update_processing_queue', json.dumps(queue_data), 'PATCH')
    return JSONResponse({"message": "PTO update request sent.", "message_id": message_id})

# Get current pay period
@app.get("/payPeriod/")
async def current_week_view():
    today = date.today()
    if today.weekday() >= 5:
        start = today + timedelta(days=(7 - today.weekday()))
    else:
        start = today - timedelta(days=today.weekday())
    end = start + timedelta(days=4)
    return JSONResponse({"week_start_date": str(start), "week_end_date": str(end)})

# Get PTO view (get PTO details by employee_id)
@app.get("/ptoBalance/")
async def get_pto(employee_id: Optional[str] = None):
    if not employee_id:
        raise HTTPException(status_code=400, detail="employee_id is required")
    queue_data = {"employee_id": employee_id}
    message_id = send_message_to_topic('user_pto_queue', json.dumps(queue_data), 'GET')
    return JSONResponse({"message": "PTO retrieval request sent.", "message_id": message_id})

# Update TimeLog View (patch update for TimeLog)
@app.patch("/timelogs/update/{pk}/")
async def update_timelog(pk: int, request: Request, user: Employee = Depends(get_current_user)):
    data = await request.json()
    if not data:
        raise HTTPException(status_code=400, detail="Time log data is required.")
    queue_data = {"timelog_id": pk, "data": data}
    message_id = send_message_to_topic('timelog_update_queue', json.dumps(queue_data), 'PATCH')
    logger.info("Sending patch to timelog_update_queue for TimeLogUpdateView")
    return JSONResponse({"message": "Time log update request sent.", "message_id": message_id})

# Bulk PTO View (POST endpoint for bulk PTO update, restricted to HR)
@app.post("/bulk_pto/")
async def bulk_pto(request: Request, user: Employee = Depends(get_current_user)):
    if user.role != RoleEnum.HR:
        raise HTTPException(status_code=403, detail="Only HR can perform bulk PTO updates.")
    data = await request.json()
    if not data:
        raise HTTPException(status_code=400, detail="Request data cannot be empty.")
    message_id = send_message_to_topic('bulk_pto_queue', json.dumps(data), 'POST')
    logger.info(f"Bulk PTO update message published. Message ID: {message_id}")
    return JSONResponse({"message": "Bulk PTO update request sent.", "message_id": message_id})

# Alternate Employee TimeLogs View
@app.get("/employeeTimeLogs/")
async def employee_time_logs_alt(user: Employee = Depends(get_current_user)):
    session = get_session()
    if user.role == RoleEnum.HR:
        employee_ids = session.exec(select(Employee.id)).all()
    elif user.role == RoleEnum.Manager:
        subordinate_ids = [sub.id for sub in user.subordinates] if user.subordinates else []
        employee_ids = [user.id] + subordinate_ids
    else:
        employee_ids = [user.id]
    queue_data = {"role": user.role, "employee_ids": employee_ids}
    message_id = send_message_to_topic('employee_timelog_list_queue', json.dumps(queue_data), 'GET')
    return JSONResponse({"message": "Time log list request sent.", "message_id": message_id})

# Alternate PTO Update View (restricted to HR)
@app.patch("/employees/{employee_id}/pto/update/")
async def pto_update_view(employee_id: int, request: Request, user: Employee = Depends(get_current_user)):
    if user.role != RoleEnum.HR:
        raise HTTPException(status_code=403, detail="Only HR can update PTO balance.")
    data = await request.json()
    new_balance = data.get("pto_balance")
    if new_balance is None:
        raise HTTPException(status_code=400, detail="PTO balance is required.")
    queue_data = {"employee_id": employee_id, "new_balance": new_balance}
    message_id = send_message_to_topic('pto_update_processing_queue', json.dumps(queue_data), 'PATCH')
    return JSONResponse({"message": "PTO update request sent.", "message_id": message_id})

# CurrentWeekView (alias for current pay period)
@app.get("/CurrentWeekView/")
async def current_week_endpoint():
    today = date.today()
    if today.weekday() >= 5:
        start = today + timedelta(days=(7 - today.weekday()))
    else:
        start = today - timedelta(days=today.weekday())
    end = start + timedelta(days=4)
    return JSONResponse({"week_start_date": str(start), "week_end_date": str(end)})

