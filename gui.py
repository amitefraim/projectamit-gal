import tkinter
from tkinter import *
from subprocess import call
import sys

import time


class comp_rectangle:
    rec_width_height = 35

    def __init__(self, canvas,x,y,name):
        self.canvas = canvas
        self.x = x
        self.y = y
        self.name = name

    def draw(self):
        self.gen_host_rectangle()

    def gen_host_rectangle(self):
        self.canvas.create_rectangle(self.x-self.rec_width_height/2, self.y-self.rec_width_height/2, self.x + self.rec_width_height/2, self.y + self.rec_width_height/2, fill="white")
        self.canvas.create_text(self.x, self.y, text=self.name)

    def connect_components(self,other):
        self.canvas.create_line(self.x, self.y, other.x, other.y)

def draw_topology(C,canvasWidth,canvasHeight,numOfSwitches,numOfHosts):
    numOfLevels =3
    switchDx = canvasWidth / numOfSwitches;
    switchDy = canvasHeight / numOfLevels;

    s0 = comp_rectangle(C, canvasWidth / 2, switchDy / 2, "s0")

    attacker = comp_rectangle(C, canvasWidth / 3, switchDy / 2, "virus")
    legitimate = comp_rectangle(C, canvasWidth * 2 / 3, switchDy / 2, "client")

    s0 = comp_rectangle(C, canvasWidth / 2, switchDy / 2, "s0")

    for i in range(1, numOfSwitches + 1):
        s1 = comp_rectangle(C, switchDx * i - switchDx / 2, switchDy * 1.5, 's%d' % i)

        s1.connect_components(s0)

        hostDx = switchDx / numOfHosts
        for j in range(0, numOfHosts):
            s2 = comp_rectangle(C, hostDx * (j + 0.5) + switchDx * (i - 1), switchDy * 2.5, 'h%d_%d' % (j, i))
            s2.connect_components(s1)
            s2.draw()

        s1.draw()

    attacker.connect_components(s0)
    legitimate.connect_components(s0)
    attacker.draw()
    legitimate.draw()

    s0.draw()

def updateCanvas(numOfSwitches):
    canvasWidth = 1000;
    canvasHeight = 500;
    numOfSwitches = int(numOfSwitches);
    numOfLevels = 3;
    numOfHosts = 2;

    C = Canvas(root, bg="white", height=canvasHeight, width=canvasWidth);
    C.grid(row=2, column=2)
    draw_topology(C, canvasWidth, canvasHeight, numOfSwitches, numOfHosts)

def launchMininet():
    varStatus.set("Launching Mininet")
    root.update()
    sys.path.insert(0,'/home/ron/Desktop/tmp/mininet')
    call(['sudo','python', '/home/ron/PycharmProjects/sdntest/ctrl.py',varServices.get() ,'2', '2'])
    varStatus.set("Attack Successfully Blocked")
root = Tk()
# for r in range(3):
#    for c in range(4):
#       Label(root, text='R%s/C%s'%(r,c),
#          borderwidth=1 ).grid(row=r,column=c)

##Title
Label(root, text='SDN Mininet Firewall GUI',
          borderwidth=1,font=("Helvetica", 16) ).grid(row=1,column=2)


updateCanvas(1)

Label(root, text='Num Of Services',
          borderwidth=1,font=("Helvetica", 12) ).grid(row=3,column=2)

varServices = StringVar(root)
varServices.set("1") # initial value
optionServicesList = []
optionServices = OptionMenu(root, varServices ,"1", "2", "3", "4","5","6","7","8","9","10",command=updateCanvas)
optionServices.grid(row=4,column=2)
print(varServices.get())

varStatus = StringVar(root)
varStatus.set("")
statusLabel = Label(root, textvariable=varStatus,
          borderwidth=1,font=("Helvetica", 12) )
statusLabel.grid(row=6,column=2)


launchButton = Button(root, text ="Launch", command = launchMininet)
launchButton.grid(row=5,column=2)

#arc = C.create_arc(coord, start=0, extent=150, fill="red")
#connect_components(C,200,200,300,300)
#gen_host_rectangle(C,200,200,"s0")
#gen_host_rectangle(C,300,300,"s1")
root.mainloop(  )
