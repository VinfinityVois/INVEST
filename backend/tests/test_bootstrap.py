import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import User
from app.security.bootstrap import create_bootstrap_admin
from app.security.passwords import verify_password


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    with TestingSession() as session:
        yield session

    engine.dispose()


def test_bootstrap_creates_first_admin(db):
    with db.begin():
        user = create_bootstrap_admin(
            db,
            " ADMIN@example.test ",
            "StrongBootstrapPassword123!",
        )

        assert user.email == "admin@example.test"
        assert user.is_admin is True
        assert user.is_active is True
        assert verify_password(
            "StrongBootstrapPassword123!",
            user.password_hash,
        )


def test_bootstrap_refuses_when_admin_already_exists(db):
    with db.begin():
        db.add(
            User(
                email="existing@example.test",
                password_hash="not-used",
                is_active=True,
                is_admin=True,
            )
        )

    with pytest.raises(ValueError, match="administrator already exists"):
        with db.begin():
            create_bootstrap_admin(
                db,
                "second@example.test",
                "StrongBootstrapPassword123!",
            )

    assert db.execute(select(User)).scalars().all().__len__() == 1


def test_bootstrap_refuses_existing_non_admin_email(db):
    with db.begin():
        db.add(
            User(
                email="existing@example.test",
                password_hash="not-used",
                is_active=True,
                is_admin=False,
            )
        )

    with pytest.raises(ValueError, match="user with this email already exists"):
        with db.begin():
            create_bootstrap_admin(
                db,
                "EXISTING@example.test",
                "StrongBootstrapPassword123!",
            )

    users = db.execute(select(User)).scalars().all()
    assert len(users) == 1
    assert users[0].is_admin is False


@pytest.mark.parametrize(
    "password",
    ["short", "", "x" * 1025],
)
def test_bootstrap_rejects_weak_or_oversized_password(db, password):
    with pytest.raises(ValueError, match="Password must contain"):
        with db.begin():
            create_bootstrap_admin(db, "admin@example.test", password)

    assert db.execute(select(User)).scalars().all() == []


def test_bootstrap_normalizes_email(db):
    with db.begin():
        user = create_bootstrap_admin(
            db,
            "  ADMIN@EXAMPLE.TEST ",
            "StrongBootstrapPassword123!",
        )

    assert user.email == "admin@example.test"


def test_concurrent_bootstrap_creates_exactly_one_admin(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    engine = create_engine(
        f"sqlite:///{tmp_path / 'bootstrap-race.db'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    Base.metadata.create_all(engine)

    ConcurrentSession = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )
    barrier = Barrier(2)

    def attempt(email):
        with ConcurrentSession() as session:
            barrier.wait(timeout=10)
            try:
                with session.begin():
                    create_bootstrap_admin(
                        session,
                        email,
                        "StrongBootstrapPassword123!",
                    )
                return "created"
            except ValueError:
                return "refused"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(
                attempt,
                ["first@example.test", "second@example.test"],
            ))

        assert results.count("created") == 1
        assert results.count("refused") == 1

        with ConcurrentSession() as session:
            admins = session.execute(
                select(User).where(User.is_admin.is_(True))
            ).scalars().all()

        assert len(admins) == 1
    finally:
        engine.dispose()
