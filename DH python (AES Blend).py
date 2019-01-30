import time
import serial
from random import getrandbits
import unicodedata
import struct
from random import randint
from Crypto.Cipher import AES

#****** GLOBAL VARIABLES *******************************************************

g = 5
prime = 0xffffffffffffffc5
bits = 10
print ("g = ", g)
print ("prime = ", prime)


#****** FUNCTIONS **************************************************************

def SerialStart():
    global ser
    ser = serial.Serial(
         port='/dev/ttyS0',
         baudrate = 9600,
         parity=serial.PARITY_NONE,
         stopbits=serial.STOPBITS_ONE,
         bytesize=serial.EIGHTBITS,
         timeout=0.1
         )
    counter=0

def bRandBCalc():
    global b
    global B
    b = randint(0,100)
    B = pow(g, b, prime)


def ten_or_less_digits_limitation():
    while len(str(B)) > 9:     #secret key works if len is 10 or less digits
        bRandBCalc()
    print ("==========================================================================")   
    print ("b = ", b)
    print ("B =     ", B)
    

def num2str():
    global Bstr
    global Blenstr
    Bstr = str(B)   #integer to string
    Blenstr = str(len(str(B)))  #length of B interger
    print("Bstr = ", Bstr)
    print("Length of B = ", Blenstr)
    print (" ")

def BLengthOK():
    global OK
    while 1:
        #Send length of B over to MSP430
        ser.write(Blenstr)
        #Receives OK
        OK = ser.readline(32)
        if OK:
            print("OK: ",OK)
            break

def SendB_ReceiveA():
    global num
    global num1
    ser.write(Bstr)
    num = ser.readline(32)
    num1 = num.encode('hex', errors='strict')
    
def Unicode_Hex_HexList_ReverseHexList_Str_Int():
    global hexsplit
    global reversehexsplit
    global reversehexstr
    global hextstr2int
    global hexstr2int
    global breakconfirm
    breakconfirm = 1
    if num1:    #got something in variable
        print("num:  ", num)    #original received in unicode
        print("num1: ", num1)   #change to hex from unicode string
        hexsplit = [num1[i:i+2] for i in range(0,len(num1),2)]  #split hex into list
        reversehexsplit = list(reversed(hexsplit))
        print ("reversehexsplit: ", reversehexsplit) #separated. as received from MSP430
        reversehexstr = (''.join(reversehexsplit))
        print("reversehexstr: ", reversehexstr)
        hexstr2int = int(reversehexstr, 16)
        print("hexstr2int: ", hexstr2int)  
        breakconfirm = 2
            
def SendB_GetA_ConversionsA():
    while 1:
        SendB_ReceiveA()    #Send B over, Recieves A in unicode format
        Unicode_Hex_HexList_ReverseHexList_Str_Int()    #Converts Unicode to Hex to HexList to ReverseHexList (original MSP430) to String to Integer
        if breakconfirm == 2:
            break
        
def SerialClose():
    ser.close()

def SecretKeyGen():
    global A
    global sB
    global sBb
    A = hexstr2int + 0  # copy hexstr2int to A. (A = hexstr2int)
    sB = pow(A, b, prime)
    print("sB = ", sB)
    #sBb = ((pow(A,b)) % prime)
    #print("sBb = ", sBb)

def DiffieHellmanPython():
    SerialStart()   #Serial start function
    bRandBCalc()    #get random 'b' and Calculate 'B'
    ten_or_less_digits_limitation() #check for 10 or less digit (limitation of secret key gen)        
    num2str()   #Change B to str, for length of B.
    BLengthOK() #send length of B to MSP430, then recieve OK signal from MSP430
    #Continue DH
    SendB_GetA_ConversionsA() #Send B, Get A, convert A to Int        
    SerialClose()   #close the serial, no more communication
    SecretKeyGen()  #calculate SecretKeys for CipherKey

def int2ascii():
    global secretkeys
    global secretkeys_str_list_asciichar_string
    secretkeys = sB + 0   #sB secret key is an integer
    secretkeys_str = str(secretkeys)    #integer to string

    length = (len(secretkeys_str)%2)     #if sB length is even or odd
    if (length == 0):    #"even"
        secretkeys_str_list = [secretkeys_str[i:i+2] for i in range(0, len(secretkeys_str),2)]  #string to list
    else:               #"odd"
        temp = '0' + secretkeys_str #will add a '0' infront of the string so that the split will be the same with msp430
        secretkeys_str_list = [temp[i:i+2] for i in range(0, len(temp),2)]  #string to list        
    secretkeys_str_list_intlist = map(int, secretkeys_str_list) #convert string list to int list
    secretkeys_str_list_asciichar = [chr(c) for c in secretkeys_str_list_intlist]   #int list to ascii char list
    secretkeys_str_list_asciichar_string = (''.join(map(str, secretkeys_str_list_asciichar))) #join ascii char list to string
    print("secretkeys = ", secretkeys)
    print("secretkeys_str = ", secretkeys_str)
    print("secretkeys_str_list = ", secretkeys_str_list)
    print("secretkeys_str_list_asciichar = ", secretkeys_str_list_asciichar)
    print("secretkeys_str_list_asciichar_string = ", secretkeys_str_list_asciichar_string)

def concantatecopy():
    global tempsecret
    tempsecret =  secretkeys_str_list_asciichar_string + ''

def stringlength():
    global tempsecretlen
    tempsecretlen = len(tempsecret)
    print("tempsecretlen = ", tempsecretlen)

def concantateadd():
    global string2
    global tempsecret
    global secretkeys_str_list_asciichar_string
    string2 = secretkeys_str_list_asciichar_string + ''
    tempsecret = tempsecret + string2
    stringlength()
    tempsecretlen = len(tempsecret)

def DHkey32ascii():
    global tempsecret
    global finalsecret
    finalsecret = tempsecret[:32]
    print("Final DH Key in ASCII: ", finalsecret)

def print_final_secret_length():
    lenDHkey32ascii = len(finalsecret)  
    print("finalsecret length:",lenDHkey32ascii)
    
#****** MAIN *******************************************************************

DiffieHellmanPython()           #DH algorithm to get sB

int2ascii()                     #store sB into secretkeys to convert to ascii

concantatecopy()                #COPY 1st sB into tempsecret

stringlength()                  #check tempsecret length (cipher)

while tempsecretlen < 32:       #if length of cipher < 32, 
    DiffieHellmanPython()       #do DH again
    int2ascii()                 #Then, store sB into secretkey to convert to ascii
    concantateadd()             #ADD new DH ascii into tempsecret
    
print("tempsecret =           ", tempsecret)

DHkey32ascii()                  #Only want exactly 32 bytes of ASCII for CipherKey

print_final_secret_length()     #prints the final cipher key length

#****** AES ENCRYPTION TEST *******************************************************
SerialStart()

key = finalsecret + ''                          #our cipher key
print("")
print("Final secret/key: ",key)

cipher = AES.new(key, AES.MODE_ECB)             #Load the key & Pass the value MODE_ECB to use the electronic code book mode.
msg = cipher.encrypt('HelloWorld654321')        #RPi msg encrypt
print("msg by RPi(c): ",msg)
print("msg by RPi(x): ", msg.encode("hex"))   #print the RPi encoded message (HelloWorld654321)

                                                #*send the Rpi msg (HelloWorld654321) to MSP*

while 1:
                                                #Send encrypted msg(RPi) over to MSP430
    ser.write(msg)
                                                #*recieve the MSP's msg (HelloWorld123456)*
    MSPmsg = ser.readline(32)
    if MSPmsg:                                  #if MPSmsg1 has something, break the for loop.
                                                #split ascii(unicode) into list, filter first 16 bytes only.
        msg1split = [MSPmsg[i:i+2] for i in range(0,16,2)]  
        msgsplitjoin = (''.join(msg1split))     
        msgsplitjoinencode = msgsplitjoin.encode('hex', errors='strict')
        break
print("")
print("Raw MSP430 Msg:       ", MSPmsg)
decipher = AES.new(key,AES.MODE_ECB)                #use the same Cipher Key to decode
AESdecrypted = decipher.decrypt(msgsplitjoin)       #decrypt the unicode *important*
print("Decrypted MSP430 Msg: ", AESdecrypted)       #decipher, decrpt and print the decrypted message

SerialClose()


    


