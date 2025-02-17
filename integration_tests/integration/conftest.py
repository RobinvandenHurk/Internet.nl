import pytest
import time
import subprocess

# primary URL for internet.nl test website
APP_DOMAIN = "internet.test"

APP_URL = f"https://{APP_DOMAIN}"
INTEGRATIONTEST_APP_URL = "http://localhost:8081"

# additional subdomains that serve the test website
APP_URL_SUBDOMAINS = [
    "https://en.internet.test",
    "https://nl.internet.test",
    "https://www.internet.test",
    "https://ipv6.internet.test",
]

# domain used for the test target web server
TEST_DOMAIN = "target.test"

# domain used for the test target email server
TEST_EMAIL = "mail-target.test"

# exclude lines matching this grep extended regex so debug logging is not so crowded
REGEX_LOGGING_EXCLUDE = "GET /static"


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Overwrite default context to ignore TLS errors."""
    return {**browser_context_args, "ignore_https_errors": True}


@pytest.fixture
def page(context):
    """Overwrite default page to add logging of console messages and requests."""
    page = context.new_page()
    page.on("console", lambda msg: print(f"Console message: {msg.text}, type: {msg.type}"))
    page.on("requestfinished", lambda request: print(f"Request: {request.url}, status: {request.response().status}"))
    yield page


@pytest.fixture(scope="session")
def app_url(request):
    return APP_URL


@pytest.fixture(scope="session")
def app_domain():
    return APP_DOMAIN


@pytest.fixture(scope="session", params=APP_URL_SUBDOMAINS)
def app_url_subdomain(request):
    return request.param


@pytest.fixture(scope="function")
def test_domain(unique_id):
    return f"{unique_id}.{TEST_DOMAIN}"


@pytest.fixture(scope="function")
def test_email(unique_id):
    return f"{unique_id}.{TEST_EMAIL}"


@pytest.fixture(scope="function")
def unique_id():
    """Generate a unique (enough) ID so multiple test instances running at the same time don't
    conflict on resources (eg: Docker network/compose project name, etc)"""
    return str(int(time.time()))


@pytest.fixture(autouse=True, scope="session")
def docker_compose_logs():
    """This fixture is automatically added to each test. It will capture most relevant logs from
    Docker containers during the test run and print them so they may be presented on test failure."""

    # tail the container logs for application container and webserver, and output to stdout to have Pytest capture it
    command = (
        "docker compose --ansi=never --project-name=internetnl-test"
        " logs --follow --tail=0 app worker beat resolver webserver"
        f"| grep --extended-regexp --invert-match '{REGEX_LOGGING_EXCLUDE}'"
    )
    process = subprocess.Popen(command, shell=True, universal_newlines=True)

    yield process

    process.terminate()


def print_results_url(page):
    print(f"\nResults page url: {page.url.replace(APP_URL,  INTEGRATIONTEST_APP_URL)}")


@pytest.fixture(scope="session")
def docker_compose_exec():
    """Execute specific command in a service container"""

    yield lambda service, command: subprocess.check_output(
        f"docker compose --ansi=never --project-name=internetnl-test exec {service} {command}", shell=True
    )


@pytest.fixture(scope="session")
def trigger_cron(docker_compose_exec):
    """Trigger specific cron job manually"""

    yield lambda cron: docker_compose_exec("cron", f"/etc/periodic/{cron}")


@pytest.fixture(scope="session")
def trigger_scheduled_task(docker_compose_exec):
    """Run specific celery beat task"""

    def _trigger_scheduled_task(beat_task):
        command = (
            "from internetnl.celery import app;"
            f'task = app.signature(app.conf.beat_schedule["{beat_task}"]["task"]);'
            "task.apply_async().get();"
        ).replace("\n", "")
        docker_compose_exec("beat", f"./manage.py shell --command='{command}'")

    yield _trigger_scheduled_task


@pytest.fixture(scope="function")
def clear_webserver_cache(docker_compose_exec):
    docker_compose_exec("webserver", "find /var/tmp/nginx_cache -delete")
