from flask import Flask, render_template, request, flash
from datetime import date

app = Flask(__name__)
app.secret_key = "f728qojx6y82q39oxnjyqo923"


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/work')
def work():
    return render_template('work.html')

@app.route('/personal')
def personal():
    return render_template('personal.html')

if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0')