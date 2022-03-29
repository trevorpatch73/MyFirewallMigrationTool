from sqlalchemy import *
from sqlalchemy.orm import *
from os import path
import secrets

Base = declarative_base()


class FIREWALL_RULES(Base):
    __tablename__ = "FIREWALL_RULES"

    source_ip = Column(String(20), primary_key=True)
    destination_ip = Column(String(20), primary_key=True)
    protocol = Column(String(5), primary_key=True)
    port_number = Column(String(7), primary_key=True)
    rule_name = Column(String(300), nullable=True, unique=True)

    def __repr__(self):
        return f"FIREWALL_RULES(source_ip={self.source_ip!r},destination_ip={self.destination_ip!r},protocol={self.protocol!r},port_number={self.port_number!r},rule_name={self.rule_name!r})"


class FIREWALL_NATS(Base):
    __tablename__ = "FIREWALL_NATS"

    type = Column(String(10), primary_key=True)
    original_ip = Column(String(20), primary_key=True)
    translated_ip = Column(String(20), primary_key=True)
    rule_name = Column(String(300), nullable=True, unique=True)

    def __repr__(self):
        return f"FIREWALL_NATS(type={self.type!r},original_ip={self.original_ip!r},translated_ip={self.translated_ip!r},rule_name={self.rule_name!r})"


class FIREWALL_ROUTES(Base):
    __tablename__ = "FIREWALL_ROUTES"

    network_prefix = Column(String(20), primary_key=True)
    subnet = Column(String(20), primary_key=True)
    next_hop = Column(String(20), primary_key=True)
    admin_distance = Column(String(4), primary_key=True)
    name = Column(String(300), nullable=True, unique=True)

    def __repr__(self):
        return f"FIREWALL_ROUTES(network_prefix={self.network_prefix!r},subnet={self.subnet!r},next_hop={self.next_hop!r},admin_distance={self.admin_distance!r},name={self.name!r})"


engine = create_engine("sqlite:///databse.db", echo=True, future=True)
Base.metadata.create_all(engine)

with Session(engine) as session:
    entry1 = FIREWALL_RULES(
        source_ip='10.0.0.1',
        destination_ip='8.8.8.8',
        protocol='udp',
        port_number='53',
        rule_name='google-dns'
    )

    entry2 = FIREWALL_RULES(
        source_ip='10.0.0.2',
        destination_ip='8.8.8.8',
        protocol='udp',
        port_number='53',
        rule_name='google-dns'
    )

    session.add_all([entry1, entry2])

    session.commit()

    statement = select(FIREWALL_RULES)

    for rule in session.scalars(statement):
        print('AND THE RESULTS ARE:')
        print(rule)
