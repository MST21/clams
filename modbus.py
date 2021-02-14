##########################################################
# tylertracy@gmail.com

import time, struct, serial, serial.tools.list_ports

##############################################################################################


def comports():  # serial.tools.list_ports.comports() fails on some virtual com usb interfaces
    ports = []
    for port in range(1, 255):  # Windows COM ports COM1~COM256
        try:
            Serial = serial.Serial("COM" + str(port))
            ports.append("COM" + str(port))
            Serial.close()
        except serial.SerialException:
            pass
    return ports


def hexBytes(py_bytes):
    if isinstance(py_bytes, int):
        py_bytes = [py_bytes]
    return "".join("{:02X}".format(py_byte) for py_byte in py_bytes) + "H"


###########################################################################################################

REPLY_CD = {
    "SUCCESS": 0x00,
    "ILLEGAL_FUNCTION": 0x01,  # Drive side reply errors
    "ILLEGAL_ADDRESS": 0x02,
    "ILLEGAL_VALUE": 0x03,
    "BOUND_PAIR_ERROR": 0x21,
    "WRITE_ERROR": 0x22,
    "UV_DURING_WRITE_ERROR": 0x23,
    "BUSY_DURING_WRITE_ERROR": 0x24,
    "CPU_OVERLOAD_DURING_WRITE_ERROR": 0x25,
    "BASEBLOCK_CIRCUIT_ERROR": 0x32,
    "INVALID_USER_ARGS": -0x01,
    "INVALID_CRC_RESPONSE": -0x02,  # Pc side errors
    "TIMEOUT_NO_RESPONSE": -0x03,
}

REPLY_STR = {v: k for k, v in REPLY_CD.items()}


def replyCds():
    return ", ".join([str(val) for val in REPLY_CD.values()])


def replyStrs():
    return ", ".join([str(val) for val in REPLY_STR.values()])


def replyCd(reply_str):
    return REPLY_CD[reply_str]


def replyStr(reply_cd):
    return REPLY_STR[reply_cd]


###################################################################################################################################

MODBUS_CRC16 = (
    0x0000,
    0xC0C1,
    0xC181,
    0x0140,
    0xC301,
    0x03C0,
    0x0280,
    0xC241,
    0xC601,
    0x06C0,
    0x0780,
    0xC741,
    0x0500,
    0xC5C1,
    0xC481,
    0x0440,
    0xCC01,
    0x0CC0,
    0x0D80,
    0xCD41,
    0x0F00,
    0xCFC1,
    0xCE81,
    0x0E40,
    0x0A00,
    0xCAC1,
    0xCB81,
    0x0B40,
    0xC901,
    0x09C0,
    0x0880,
    0xC841,
    0xD801,
    0x18C0,
    0x1980,
    0xD941,
    0x1B00,
    0xDBC1,
    0xDA81,
    0x1A40,
    0x1E00,
    0xDEC1,
    0xDF81,
    0x1F40,
    0xDD01,
    0x1DC0,
    0x1C80,
    0xDC41,
    0x1400,
    0xD4C1,
    0xD581,
    0x1540,
    0xD701,
    0x17C0,
    0x1680,
    0xD641,
    0xD201,
    0x12C0,
    0x1380,
    0xD341,
    0x1100,
    0xD1C1,
    0xD081,
    0x1040,
    0xF001,
    0x30C0,
    0x3180,
    0xF141,
    0x3300,
    0xF3C1,
    0xF281,
    0x3240,
    0x3600,
    0xF6C1,
    0xF781,
    0x3740,
    0xF501,
    0x35C0,
    0x3480,
    0xF441,
    0x3C00,
    0xFCC1,
    0xFD81,
    0x3D40,
    0xFF01,
    0x3FC0,
    0x3E80,
    0xFE41,
    0xFA01,
    0x3AC0,
    0x3B80,
    0xFB41,
    0x3900,
    0xF9C1,
    0xF881,
    0x3840,
    0x2800,
    0xE8C1,
    0xE981,
    0x2940,
    0xEB01,
    0x2BC0,
    0x2A80,
    0xEA41,
    0xEE01,
    0x2EC0,
    0x2F80,
    0xEF41,
    0x2D00,
    0xEDC1,
    0xEC81,
    0x2C40,
    0xE401,
    0x24C0,
    0x2580,
    0xE541,
    0x2700,
    0xE7C1,
    0xE681,
    0x2640,
    0x2200,
    0xE2C1,
    0xE381,
    0x2340,
    0xE101,
    0x21C0,
    0x2080,
    0xE041,
    0xA001,
    0x60C0,
    0x6180,
    0xA141,
    0x6300,
    0xA3C1,
    0xA281,
    0x6240,
    0x6600,
    0xA6C1,
    0xA781,
    0x6740,
    0xA501,
    0x65C0,
    0x6480,
    0xA441,
    0x6C00,
    0xACC1,
    0xAD81,
    0x6D40,
    0xAF01,
    0x6FC0,
    0x6E80,
    0xAE41,
    0xAA01,
    0x6AC0,
    0x6B80,
    0xAB41,
    0x6900,
    0xA9C1,
    0xA881,
    0x6840,
    0x7800,
    0xB8C1,
    0xB981,
    0x7940,
    0xBB01,
    0x7BC0,
    0x7A80,
    0xBA41,
    0xBE01,
    0x7EC0,
    0x7F80,
    0xBF41,
    0x7D00,
    0xBDC1,
    0xBC81,
    0x7C40,
    0xB401,
    0x74C0,
    0x7580,
    0xB541,
    0x7700,
    0xB7C1,
    0xB681,
    0x7640,
    0x7200,
    0xB2C1,
    0xB381,
    0x7340,
    0xB101,
    0x71C0,
    0x7080,
    0xB041,
    0x5000,
    0x90C1,
    0x9181,
    0x5140,
    0x9301,
    0x53C0,
    0x5280,
    0x9241,
    0x9601,
    0x56C0,
    0x5780,
    0x9741,
    0x5500,
    0x95C1,
    0x9481,
    0x5440,
    0x9C01,
    0x5CC0,
    0x5D80,
    0x9D41,
    0x5F00,
    0x9FC1,
    0x9E81,
    0x5E40,
    0x5A00,
    0x9AC1,
    0x9B81,
    0x5B40,
    0x9901,
    0x59C0,
    0x5880,
    0x9841,
    0x8801,
    0x48C0,
    0x4980,
    0x8941,
    0x4B00,
    0x8BC1,
    0x8A81,
    0x4A40,
    0x4E00,
    0x8EC1,
    0x8F81,
    0x4F40,
    0x8D01,
    0x4DC0,
    0x4C80,
    0x8C41,
    0x4400,
    0x84C1,
    0x8581,
    0x4540,
    0x8701,
    0x47C0,
    0x4680,
    0x8641,
    0x8201,
    0x42C0,
    0x4380,
    0x8341,
    0x4100,
    0x81C1,
    0x8081,
    0x4040,
)


def intCrc16(packet, crc=0xFFFF):  # returns raw crc16 as py int
    for byte in packet:
        crc = (crc >> 8) ^ MODBUS_CRC16[(crc ^ byte) & 0x00FF]
    return (crc >> 8) | ((crc << 8) & 0xFF00)


def structCrc16(packet, crc=0xFFFF):  # returns py struct packet+crc16
    import struct

    for byte in packet:
        crc = (crc >> 8) ^ MODBUS_CRC16[(crc ^ byte) & 0x00FF]
    return packet + struct.pack("<H", crc)


#########################################################################################################


class ModBusSerialClient:
    def __init__(self, com: str, baud=9600, timeout=0.5, loopback=False):  # timeout=0.1
        if loopback:
            self.Serial = serial.serial_for_url(
                url="loop://", baudrate=baud, timeout=timeout
            )
        else:
            self.Serial = serial.Serial(port=com, baudrate=baud, timeout=timeout)

    def close(self):
        self.Serial.close()

    def rxPacket(self, rx_packet, error_cd):
        if len(rx_packet) == 0:
            raise ValueError("\n\n\n\n\nTIMEOUT_NO_RESPONSE:-0x03\n\n\n")
        elif (
            intCrc16(rx_packet[:-2])
            != struct.unpack_from(">H", rx_packet, len(rx_packet) - 2)[0]
        ):
            raise ValueError(
                "\n\n\n\n\nINVALID_CRC_RESPONSE:-0x02 => rx: 0x"
                + hexBytes(rx_packet)
                + "\n\n\n"
            )
        elif error_cd == struct.unpack_from(">B", rx_packet, 1)[0]:
            raise ValueError(
                "\n\n\n\n\n0x"
                + hexBytes((error_cd,))
                + ":"
                + replyStr(struct.unpack_from(">B", rx_packet, 2)[0])
                + " => rx: 0x"
                + hexBytes(rx_packet)
                + "\n\n\n"
            )
        return rx_packet

    #######################################################################################################################################

    def write_wReg(
        self, reg, vals, slave=0x1F
    ):  # slave=0~0xFF, reg=0~0xFFFF, val=0~65535
        if isinstance(vals, int):
            vals = [vals]  # n=1*16b_words => 2*n=2*8b_bytes
        self.Serial.write(
            structCrc16(
                struct.pack(
                    ">BBHHB" + len(vals) * "H",
                    slave,
                    0x10,
                    reg,
                    len(vals),
                    2 * len(vals),
                    *vals
                )
            )
        )
        self.rxPacket(self.Serial.read(8), 0x90)

    def read_wReg(
        self, reg, cnt=1, slave=0x1F
    ):  # slave=0~0xFF, parm=0~0xFFFF,  val=0~65535
        self.Serial.write(structCrc16(struct.pack(">BBHH", slave, 0x03, reg, 1)))
        return struct.unpack_from(
            ">" + cnt * "H", self.rxPacket(self.Serial.read(7), 0x83), 3
        )

    #######################################################################################################################################

    def write_sReg(
        self, reg, vals, slave=0x1F
    ):  # slave=0~0xFF, reg=0~0xFFFF,  val=0~65535
        if isinstance(vals, int):
            vals = [vals]  # n=1*16b_words => 2*n=2*8b_bytes
        self.Serial.write(
            structCrc16(
                struct.pack(
                    ">BBHHB" + len(vals) * "h",
                    slave,
                    0x10,
                    reg,
                    len(vals),
                    2 * len(vals),
                    *vals
                )
            )
        )
        self.rxPacket(self.Serial.read(8), 0x90)

    def read_sReg(
        self, reg, cnt=1, slave=0x1F
    ):  # slave=0~0xFF, parm=0~0xFFFF, val=-32767~32768
        self.Serial.write(structCrc16(struct.pack(">BBHH", slave, 0x03, reg, 1)))
        return struct.unpack_from(
            ">" + cnt * "h", self.rxPacket(self.Serial.read(7), 0x83), 3
        )


############################################################################################################################

if __name__ == "__main__":

    print(comports())
    sensor = ModBusSerialClient("COM1")
    sensor.read_sReg(91241)
    # ModBus.close()