## Manual Docker Run

### Linux/macOS:
```
docker build -t onboarderr .
docker run -d --restart unless-stopped -p 10000:10000 --name onboarderr -v $(pwd):/app onboarderr
```
To include mounted drives:
```
docker run -d -p 10000:10000 --name onboarderr \
  --restart unless-stopped \
  -v $(pwd):/app \
  -v /mnt/e:/mnt/e \
  -v /mnt/f:/mnt/f \
  onboarderr
```

### Windows (PowerShell):
```
docker build -t onboarderr .
docker run -d --restart unless-stopped -p 10000:10000 --name onboarderr -v ${PWD}:/app onboarderr
```
Mounted Drives version:
```
docker run -d -p 10000:10000 --name onboarderr `
  --restart unless-stopped `
  -v ${PWD}:/app `
  -v E:\:/mnt/e `
  -v F:\:/mnt/f `
  onboarderr
```

### Windows (Command Prompt):
```
docker build -t onboarderr .
docker run -d --restart unless-stopped -p 10000:10000 --name onboarderr -v %cd%:/app onboarderr
```
Mounted Drives version:
```
docker run -d -p 10000:10000 --name onboarderr ^
  --restart unless-stopped ^
  -v %cd%:/app ^
  -v E:\:/mnt/e ^
  -v F:\:/mnt/f ^
  onboarderr
```

- **If you change the drives in `.env`, make sure your Docker volumes match!**
- The site will be available at `localhost:10000` (or your configured port)