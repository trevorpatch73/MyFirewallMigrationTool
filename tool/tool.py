from sqlalchemy import *
from sqlalchemy.orm import *
from pathlib import Path
import secrets
import re

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

# with Session(engine) as session:
#    entry1 = FIREWALL_RULES(
#        source_ip='10.0.0.1',
#        destination_ip='8.8.8.8',
#        protocol='udp',
#        port_number='53',
#        rule_name='google-dns'
#    )

#    session.add_all([entry1, entry2])

#    session.commit()

f = open("C://Users//trevo//Documents//GitHub//ASA-EOX_TO_FMC-FTD_CONVERSION_TOOL//tool//config.txt", "r")

Lines = f.readlines()

count = 0
for line in Lines:
    count += 1
    print("Line{}: {}".format(count, line.strip()))

print("---------------------------")
print("---------------------------")
print("---------------------------")

with open("C://Users//trevo//Documents//GitHub//ASA-EOX_TO_FMC-FTD_CONVERSION_TOOL//tool//config.txt") as fh:
    string = fh.readlines()

pattern1 = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

count1 = 0

for line in string:
    line = line.rstrip()
    condition1 = pattern1.search(line)
    if condition1:
        count1 += 1
        #print("Line{}: {}".format(count1, line))
        lst = line.split(' ')
        count2 = 0
        for element in lst:
            #print('Line Element{}: {}'.format(count2, element))
            count2 += 1
        with Session(engine) as session:
            entry = FIREWALL_ROUTES(
                network_prefix=lst[1],
                subnet=lst[2],
                next_hop=lst[3],
                admin_distance=lst[0],
                name=(lst[4] + lst[5])
            )
            session.add_all([entry])
            session.commit()
