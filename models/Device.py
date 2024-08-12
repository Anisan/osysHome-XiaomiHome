from app.database import Column, Model, SurrogatePK, db

class Device(SurrogatePK, db.Model):
    __tablename__ = 'xidevices'
    title = Column(db.String(100))
    type = Column(db.String(100))
    sid = Column(db.String(255))
    gate_key = Column(db.String(100))
    gate_ip = Column(db.String(100))
    token = Column(db.String(100))
    parent_id = Column(db.Integer)
    updated = Column(db.DateTime)
