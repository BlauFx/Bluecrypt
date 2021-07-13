# Bluecrypt

# Getting started
- Install the [.NET 5 SDK](https://dotnet.microsoft.com/download/dotnet/5.0)
- Clone the repository
```
git clone https://github.com/BlauFx/Bluecrypt.git
```

build and run:
```
dotnet run --project Bluecrypt
```
# Parameters

```
--hash              Checks if the provided hashfile equals the password. If the hashfile and the password are equal then the program will continue the execution, if not it will abort. This is useful if you have a file that you want to encrypt each time with the same password but you also want to make sure that the provided password is correct in case you accidentally provided a wrong password.  
--generate--hash    Generate a hash on startup. A "passwordhashSHA512.txt" file is going to be generated in the same location where the executable is located. If the "passwordhashSHA512.txt" file is already present, it will be overwritten each time, so be cautious!
```
