from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "UrunGetir backend ayakta 🚀"}

@app.get("/hello")
def hello():
    return {"message": "Merhaba Hakan! Backend çalışıyor 😎"}
