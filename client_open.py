from tkinter import *
from tkinter import messagebox
from multiprocessing import Process
import ast
import smtplib
import random
from tkinter import filedialog
import ast
from tkinter import font as tkFont
import smtplib
import random
import time
import os
import tqdm
import socket
import threading
from tkinter import *
from tkinter import font
from tkinter import ttk 
import ast
import smtplib
import random
import os
import tqdm

root=Tk()
root.title('Login')
root.geometry('2160x1680')
root.configure(bg="#fff")
root.resizable(True,True)
helv36 = tkFont.Font(family='Helvetica', size=16, weight=tkFont.BOLD)

###################3



def chat_page():
	PORT = 5000
	SERVER = "172.16.181.49"
	ADDRESS = (SERVER, PORT)
	FORMAT = "utf-8"

	# Create a new client socket
	# and connect to the server
	client = socket.socket(socket.AF_INET,
						socket.SOCK_STREAM)
	client.connect(ADDRESS)
	# GUI class for the chat

#############################################################


	def send_file():
		SEPARATOR = "<SEPARATOR>"
		BUFFER_SIZE = 4096 # send 4096 bytes each time step
		# the ip address or hostname of the server, the receiver
		host=SERVER
		# the port, let's use 5001
		port =PORT
		# the name of file we want to send, make sure it exists


		global filename
		filename=filedialog.askopenfilename(initialdir=os.getcwd(),title="Select Image File",
											filetypes=(("file_type","*.txt"),("all files","*.*")))


		filesize = os.path.getsize(filename)
		# exit()
		# create the client socket
		s = socket.socket()
		print(f"[+] Connecting to {host}:{port}")
		s.connect((host, port))
		print("[+] Connected.")
		# send the filename and filesize
		s.send(f"{filename}{SEPARATOR}{filesize}".encode())
		# start sending the file
		progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
		with open(filename, "rb") as f:
			while True:
				# read the bytes from the file
				bytes_read = f.read(BUFFER_SIZE)
				if not bytes_read:
					# file transmitting is done
					break
				# we use sendall to assure transimission in 
				# busy networks
				s.sendall(bytes_read)
				# update the progress bar
				progress.update(len(bytes_read))

		s.close()


 ##################################################
 
 
	class GUI:
		# constructor method
		def __init__(self):

			# chat window which is currently hidden
			self.Window = Tk()
			self.Window.withdraw()

			# login window
			self.login = Toplevel()
			# set the title
			self.login.title("Login")
			self.login.resizable(width=False,
								height=False)
			self.login.configure(width=400,
								height=300)
			# create a Label
			self.pls = Label(self.login,
							text="Please enter login",
							justify=CENTER,
							font="Helvetica 14 bold")

			self.pls.place(relheight=0.15,
						relx=0.2,
						rely=0.07)
			# create a Label
			self.labelName = Label(self.login,
								text="Name: ",
								font="Helvetica 12")

			self.labelName.place(relheight=0.2,
								relx=0.1,
								rely=0.2)

			# create a entry box for
			# tyoing the message
			self.entryName = Entry(self.login,
								font="Helvetica 14")

			self.entryName.place(relwidth=0.4,
								relheight=0.12,
								relx=0.35,
								rely=0.2)

			# set the focus of the cursor
			self.entryName.focus()

			# create a Continue Button
			# along with action
			self.go = Button(self.login,
							text="CONTINUE",
							font="Helvetica 14 bold",
							command=lambda: self.goAhead(self.entryName.get()))

			self.go.place(relx=0.4,
						rely=0.55)
			self.Window.mainloop()

		def goAhead(self, name):
			self.login.destroy()
			self.layout(name)

			# the thread to receive messages
			rcv = threading.Thread(target=self.receive)
			rcv.start()

		# The main layout of the chat
		def layout(self, name):

			self.name = name
			# to show chat window
			self.Window.deiconify()
			self.Window.title("CHATROOM")
			self.Window.resizable(width=False,
								height=False)
			self.Window.configure(width=470,
								height=550,
								bg="#17202A")
			self.labelHead = Label(self.Window,
								bg="#17202A",
								fg="#EAECEE",
								text=self.name,
								font="Helvetica 13 bold",
								pady=5)

			self.labelHead.place(relwidth=1)
			self.line = Label(self.Window,
							width=450,
							bg="#ABB2B9")

			self.line.place(relwidth=1,
							rely=0.07,
							relheight=0.012)

			self.textCons = Text(self.Window,
								width=20,
								height=2,
								bg="#17202A",
								fg="#EAECEE",
								font="Helvetica 14",
								padx=5,
								pady=5)

			self.textCons.place(relheight=0.745,
								relwidth=1,
								rely=0.08)

			self.labelBottom = Label(self.Window,
									bg="#ABB2B9",
									height=80)

			self.labelBottom.place(relwidth=1,
								rely=0.825)

			self.entryMsg = Entry(self.labelBottom,
								bg="#2C3E50",
								fg="#EAECEE",
								font="Helvetica 13")

			# place the given widget
			# into the gui window
			self.entryMsg.place(relwidth=0.74,
								relheight=0.06,
								rely=0.008,
								relx=0.011)

			self.entryMsg.focus()

			# create a Send Button
			self.buttonMsg = Button(self.labelBottom,
									text="Send",
									font="Helvetica 10 bold",
									width=16,
									bg="#ABB2B9",
									command=lambda: self.sendButton(self.entryMsg.get()))

			self.buttonMsg.place(relx=0.77,
								rely=0.008,
								relheight=0.06,
								relwidth=0.22)
##############################################
			
			self.buttonMsg = Button(self.labelBottom,
									text="attach",
									font="Helvetica 10 bold",
									width=4,
									bg="#ABB2B9",
									command=send_file)
	
									

			self.buttonMsg.place(relx=0.6,
								rely=0.008,
								relheight=0.06,
								relwidth=0.14)




###########################################



			self.textCons.config(cursor="arrow")

			# create a scroll bar
			scrollbar = Scrollbar(self.textCons)

			# place the scroll bar
			# into the gui window
			scrollbar.place(relheight=1,
							relx=0.974)

			scrollbar.config(command=self.textCons.yview)

			self.textCons.config(state=DISABLED)

		# function to basically start the thread for sending messages
		def sendButton(self, msg):
			self.textCons.config(state=DISABLED)
			self.msg = msg
			self.entryMsg.delete(0, END)
			snd = threading.Thread(target=self.sendMessage)
			snd.start()

		# function to receive messages
		def receive(self):
			while True:
				try:
					message = client.recv(1024).decode(FORMAT)

					# if the messages from the server is NAME send the client's name
					if message == 'NAME':
						client.send(self.name.encode(FORMAT))
					else:
						# insert messages to text box
						self.textCons.config(state=NORMAL)
						self.textCons.insert(END,
											message+"\n\n")

						self.textCons.config(state=DISABLED)
						self.textCons.see(END)
				except:
					# an error will be printed on the command line or console if there's an error
					print("An error occurred!")
					client.close()
					break

		# function to send messages
		def sendMessage(self):
			self.textCons.config(state=DISABLED)
			while True:
				message = (f"{self.name}: {self.msg}")
				client.send(message.encode(FORMAT))
				break

	g=GUI()			
	# create a GUI class object





###################
def signin():
    username=user.get()
    password=code.get()

    file=open('datasheet.txt','r+')
    d=file.read()
    r=ast.literal_eval(d)
    file.close()

    #print(r.keys())
    #print(r.values())
    
    # finding ussename and password in file

    if username in r.keys() and password==r[username]:
        chat_page()
    else:
        messagebox.showerror("Invalid","Invalid Username or password")

##if new login is done
    
def signup_command():
    window=Toplevel(root)
    window.title("SignUp")
    window.geometry('2160x1080')
    window.configure(bg='#fff')
    window.resizable(True,True)

    def signup():
        username=user.get()
        password=code.get()
        conform_password=conform_code.get()

        if password==conform_password:
            try:
                file=open('datasheet.txt','r+')
                d=file.read()
                r=ast.literal_eval(d)

                dict2={username:password}
                r.update(dict2)
                file.truncate(0)
                file.close()

                file=open('datasheet.txt','w')
                w=file.write(str(r))

                messagebox.showinfo('Signup','Successfully sign up')
                window.destroy()
                root.geometry('925x500+300+200')
                
            ###if file is not present then it will create file
            except:
                file=open('datasheet.txt','w')
                pp=str({'Username':'password'})
                file.write(pp)
                file.close()

        else:
            messagebox.showerror('Invalid',"Both Password should match")        

    ### if we click signin then signup should close
    def sign():
       window.destroy()


    # img=PhotoImage(file='login.png')
    # Label(window,image=img,bg='white').place(x=50,y=50)

    # #placing the login icon on the page
    # frame=Frame(window,width=450,height=350,bg="white")
    # frame.place(x=480,y=70)
    img=PhotoImage(file='login.png')
    Label(window,image=img,bg='white').place(x=-10,y=-10)

    #placing the login icon on the page
    frame=Frame(window,width=450,height=350,bg="#c7ecee")
    frame.place(relx=0.35,rely=0.2)

    heading=Label(frame,text='Sign up',fg='#0652DD', bg='#c7ecee', font=('Microsoft YaHei UI Light',23,'bold'))
    heading.place(x=125,y=5)

    ######################

    def on_enter(e):
        conform_code.delete(0, 'end')

    def on_leave(e):
            name=conform_code.get()
            if name=='':
                conform_code.insert(0,'Conform Password')

    conform_code= Entry(frame,width=35,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 11,"bold"))
    conform_code.place(x=60, y=170)
    conform_code.insert(0,'Conform Password')
    conform_code.bind('<FocusIn>', on_enter)
    conform_code.bind('FocusOut', on_leave)

    ###############################
    def on_enter(e):
        user.delete(0, 'end')

    def on_leave(e):
            name=user.get()
            if name=='':
                user.insert(0,'E-mail')

    user= Entry(frame,width=35,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 11,"bold"))
    user.place(x=60, y=70)
    user.insert(0,'E-mail')
    user.bind('<FocusIn>', on_enter)
    user.bind('FocusOut', on_leave)

    ###########################
    def on_enter(e):
        code.delete(0, 'end')

    def on_leave(e):
            name=code.get()
            if name=='':
                code.insert(0,'Password')

    code= Entry(frame,width=35,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 11,"bold"))
    code.place(x=60, y=120)
    code.insert(0,'Password')
    code.bind('<FocusIn>', on_enter)
    code.bind('FocusOut', on_leave)

    #############################
    Button(frame, width=39,pady=6,text='Sign up', bg='#0652DD', fg='white', border=0, command=signup,font=('Microsoft YaHei UI Light', 10)).place(x=60, y=220)
    label=Label(frame,text="I have an accout?", fg='black', bg='#c7ecee',font=('Microsoft YaHei UI Light', 11,"bold"))
    label.place(x=105, y=270)

    sign_in= Button(frame, width=6, text='Sign in', border=0, bg='#c7ecee', cursor='hand2',fg='#0652DD',command=sign,font=('Microsoft YaHei UI Light', 11,"bold"))
    sign_in.place(x=245, y=270)

    window.mainloop()


# forget password command


def forget_command(username):
    window=Toplevel(root)
    window.title("SignUp")
    window.geometry('2160x1080')
    window.configure(bg='#fff')
    window.resizable(True,True)
 ###############################################################
    ## function to send the otp
            
    # creates SMTP session
    
    s = smtplib.SMTP('smtp.gmail.com', 587)

    # start TLS for security
    s.starttls()

    # Authentication
    s.login("suaravsuman991@gmail.com", "pajytmtqnsitrfea")

    # message to be sent
    message = random.randint(1,9)*102207
    otp_send=message
    print(otp_send)
    # sending the mail
    s.sendmail("suaravsuman991@gmail.com", username, str(otp_send))

    # terminating the session
    s.quit()  

    ############################
    def reset():
        OTP=otp.get()
        if otp_send==int(OTP):
            messagebox.showinfo('OK',"OTP validated")
        else:
            messagebox.showerror('Invalid',"Wrong OTP")
    

    ### if we click signin then signup should close
    def sign():
        password=code.get()
        conform_password=conform_code.get()
        if password==conform_password:
            try:
                file=open('datasheet.txt','r+')
                d=file.read()
                r=ast.literal_eval(d)

                #dict2={username:password}
                r.update({username:password})
                #r.update(dict2)
                file.truncate(0)
                file.close()

                file=open('datasheet.txt','w')
                w=file.write(str(r))

                messagebox.showinfo('Done','Successfully Changed')
                window.destroy()
            
        ###if file is not present then it will create file
            except:
                file=open('datasheet.txt','w')
                pp=str({'Username':'password'})
                file.write(pp)
                file.close()  

        else:
            messagebox.showerror('Invalid',"Both Password should match")
        #window.destroy()

    # img=PhotoImage(file='login.png')
    # Label(window,image=img,bg='white').place(x=50,y=50)

    # #placing the login icon on the page
    # frame=Frame(window,width=450,height=280,bg="white")
    # frame.place(x=480,y=70)
    img=PhotoImage(file='login.png')
    Label(window,image=img,bg='white').place(x=-10,y=-10)

    #placing the login icon on the page
    frame=Frame(window,width=450,height=350,bg="#c7ecee")
    frame.place(relx=0.35,rely=0.2)

    heading=Label(frame,text='Reset Password',fg='#0652DD', bg='#c7ecee', font=('Microsoft YaHei UI Light',22,'bold'))
    heading.place(x=100,y=5)  

    ######################

    
    ###################

    def on_enter(e):
        conform_code.delete(0, 'end')

    def on_leave(e):
            name=conform_code.get()
            if name=='':
                conform_code.insert(0,'Conform Password')

    conform_code= Entry(frame,width=33,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 11,"bold"))
    conform_code.place(x=60, y=180)
    conform_code.insert(0,'Conform Password')
    conform_code.bind('<FocusIn>', on_enter)
    conform_code.bind('<FocusOut>', on_leave)

    ###############################
    def on_enter(e):
        otp.delete(0, 'end')

    def on_leave(e):
            name=otp.get()
            if name=='':
                otp.insert(0,'OTP')

    otp= Entry(frame,width=33,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 11,"bold"))
    otp.place(x=60, y=80)
    otp.insert(0,'OTP')
    otp.bind('<FocusIn>', on_enter)
    otp.bind('<FocusOut>', on_leave)

    ###########################
    def on_enter(e):
        code.delete(0, 'end')

    def on_leave(e):
            name=code.get()
            if name=='':
                code.insert(0,'New Password')

    code= Entry(frame,width=33,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 11,"bold"))
    code.place(x=60, y=130)
    code.insert(0,'New Password')
    code.bind('<FocusIn>', on_enter)
    code.bind('<FocusOut>', on_leave)

    #############################
    sign_in= Button(frame, width=0, text='', border=0, bg='#c7ecee', cursor='hand2',fg='#0652DD', command=reset)
    sign_in.place(x=215, y=98)

    Button(frame, width=42,pady=6,text='Done', bg='#0652DD', fg='white', border=0,command=sign).place(x=60, y=230)
    #label=Label(frame,text="I have an accout?", fg='black', bg='white',font=('Microsoft YaHei UI Light', 9))
    #label.place(x=105, y=220)

    #sign_in= Button(frame, width=6, text='Sign in', border=0, bg='white', cursor='hand2',fg='#57a1f8',command=sign)
    #sign_in.place(x=215, y=300)

    window.mainloop()



def reset_send_otp():
    window=Toplevel(root)
    window.title("Password Reset")
    window.geometry('2160x1080')
    window.configure(bg='#fff')
    window.resizable(True,True)

    #####################
    def signup():
        username=user.get()
        file=open('datasheet.txt','r+')
        d=file.read()
        r=ast.literal_eval(d)
        file.close()
        
        if username in r.keys():
            pass
        else:
            messagebox.showerror('Invalid',"User name not found!")
            exit()     
        return username

    def sign():
        window.destroy()
    
    def send_user():
        username=signup()
        # if __name__=='__main__':
        #     p1 = Process(target=forget_command(username))
        #     p1.start()
        #     p2 = Process(target=messagebox.showinfo('OK',"OTP send"))
        #     p2.start()
        #     p2.join()
        sign()
        forget_command(username)
        

    # img=PhotoImage(file='login.png')
    # Label(window,image=img,bg='white').place(x=50,y=50)

    # #placing the login icon on the page
    # frame=Frame(window,width=450,height=250,bg="white")
    # frame.place(x=480,y=70)
    
    img=PhotoImage(file='login.png')
    Label(window,image=img,bg='white').place(x=-10,y=-10)

    #placing the login icon on the page
    frame=Frame(window,width=450,height=350,bg="#c7ecee")
    frame.place(relx=0.35,rely=0.2)
        
    

    heading=Label(frame,text='Reset Password',fg='#0652DD', bg='#c7ecee', font=('Microsoft YaHei UI Light',21,'bold'))
    heading.place(x=100,y=18) 

    def on_enter(e):
         user.delete(0, 'end')

    def on_leave(e):
            name=user.get()
            if name=='':
                user.insert(0,'E-mail')

    user= Entry(frame,width=28,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 14))
    user.place(x=60, y=92)
    user.insert(0,'E-mail')
    user.bind('<FocusIn>', on_enter)
    user.bind('FocusOut', on_leave)  
 
    Button(frame, width=44,pady=6,text='Continue ', bg='#0652DD', fg='white', border=0,command=send_user).place(x=60, y=165)
    #label=Label(frame,text="I have an accout?", fg='black', bg='white',font=('Microsoft YaHei UI Light', 9))
    #label.place(x=60, y=100)

    sign_in= Button(frame, width=6, text='Back', border=0, bg='#c7ecee', cursor='hand2',fg='#0652DD',font=('Microsoft YaHei UI Light', 11,"bold"),command=sign)
    sign_in.place(x=5, y=8)

    # sign_in= Button(frame, width=8, text='Send OTP', border=0, bg='white', cursor='hand2',fg='#57a1f8', command=reset)
    # sign_in.place(x=215, y=98)

    window.mainloop()
##adding image to the login page

img=PhotoImage(file='login.png')
Label(root,image=img,bg='white').place(x=-10,y=-10)

#placing the login icon on the page
frame=Frame(root,width=450,height=350,bg="#c7ecee")
frame.place(relx=0.35,rely=0.2)


heading=Label(frame,text='Sign in',fg='#0652DD', bg='#c7ecee', font=('Microsoft YaHei UI Light',23,'bold'))
heading.place(x=170,y=5)


def on_enter(e):
    user.delete(0,'end')

def on_leave(e):
        name=user.get()
        if (name==""):
            user.insert(0,"E-mail")

user= Entry(frame,width=40,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 11))
user.place(x=60, y=70)
user.insert(0,"E-mail")
user.bind("<FocusIn>", on_enter)
user.bind("<FocusOut>", on_leave)

def on_enter(e):
    code.delete(0,'end')

def on_leave(e):
        name=code.get()
        if name=="":
            code.insert(0,'Password')

code= Entry(frame,width=40,fg='black', border=2,bg="white",font=('Microsoft YaHei UI Light', 11))
code.place(x=60, y=130)
code.insert(0,'Password')
code.bind('<FocusIn>', on_enter)
code.bind('<FocusOut>', on_leave)

#######################

Button(frame, width=35,height=-5,pady=6,text='Log In', bg='#0652DD',font=('Microsoft YaHei UI Light', 10, "bold"), fg='white', border=0,command=signin).place(x=60, y=180)
label=Label(frame,text="Don't have an accout?", fg='black', bg='#c7ecee',font=('Microsoft YaHei UI Light', 11, "bold"))
label.place(x=98, y=261)

forget_password= Button(frame, width=25, text='Forget password!', border=0, bg='#c7ecee', cursor='hand2',fg='#0652DD',font=('Microsoft YaHei UI Light', 11, "bold"),command=reset_send_otp)
forget_password.place(x=100, y=230)

def window_destroy_signup():
    #root.geometry('0x0+0+0')
    signup_command()

sign_up= Button(frame, width=6, text='Sign up', border=0, bg='#c7ecee',font=('Microsoft YaHei UI Light', 11, "bold"), cursor='hand2',fg='#0652DD',command=window_destroy_signup)
sign_up.place(x=280, y=260)


root.mainloop()

            
