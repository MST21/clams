
from modbus import ModBusSerialClient

COM_PORT = "COM1"

if __name__ == "__main__":
    sensor = ModBusSerialClient(COM_PORT)
    level_mm = sensor.read_wReg(30300)
    print(level_mm)
