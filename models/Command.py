from app.database import Column, Model, SurrogatePK, db

class Command(SurrogatePK, db.Model):
    __tablename__ = 'xicommands'
    title = Column(db.String(100))
    value = Column(db.String(255))
    device_id = Column(db.Integer)
    linked_object = Column(db.String(100))
    linked_property = Column(db.String(100))
    linked_method = Column(db.String(100))
    updated = Column(db.DateTime)

