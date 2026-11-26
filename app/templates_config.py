import os
from jinja2 import pass_context
from starlette.templating import Jinja2Templates
from app.i18n import i18n_context_processor, localize_severity, localize_status, localize_department, localize_page_title, localize_user_name, localize_author, localize_message

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

templates = Jinja2Templates(
    directory=TEMPLATES_DIR,
    context_processors=[i18n_context_processor]
)

@pass_context
def filter_loc_sev(context, val):
    lang = context.get("lang", "en")
    return localize_severity(val, lang)

@pass_context
def filter_loc_status(context, val):
    lang = context.get("lang", "en")
    return localize_status(val, lang)

@pass_context
def filter_loc_dept(context, val):
    lang = context.get("lang", "en")
    return localize_department(val, lang)

@pass_context
def filter_loc_title(context, val):
    lang = context.get("lang", "en")
    return localize_page_title(val, lang)

@pass_context
def filter_loc_user(context, val):
    lang = context.get("lang", "en")
    return localize_user_name(val, lang)

@pass_context
def filter_loc_author(context, val):
    lang = context.get("lang", "en")
    return localize_author(val, lang)

@pass_context
def filter_loc_msg(context, val):
    lang = context.get("lang", "en")
    return localize_message(val, lang)

# Custom Jinja2 filters
templates.env.filters["loc_sev"] = filter_loc_sev
templates.env.filters["loc_status"] = filter_loc_status
templates.env.filters["loc_dept"] = filter_loc_dept
templates.env.filters["loc_title"] = filter_loc_title
templates.env.filters["loc_user"] = filter_loc_user
templates.env.filters["loc_author"] = filter_loc_author
templates.env.filters["loc_msg"] = filter_loc_msg



