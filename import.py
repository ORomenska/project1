import os
import csv
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session,sessionmaker

engine=create_engine(os.getenv("DATABASE_URL"))
db=scoped_session(sessionmaker(bind=engine))
def main():
    with open("books.csv") as f:
        reader=csv.reader(f)
        next(reader,None)
        for isbn,title,author,year in reader:
            try:
                db.execute("INSERT INTO books(isbn,title,author,year) VALUES(:isbn,:title,:author,:year)",{"isbn":isbn,"title":title,"author":author,"year":year})
                print("Book was added")
                db.commit()
            except:
                db.rollback()
                raise
            finally:
                db.close()
                db.remove()
if __name__=="__main__":
    main()