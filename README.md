# Crypt

Encrypt and decrypt messages.

Crypt is a thin layer over Java's crypto libraries.
Crypt provides various tools to encrypt and decrypt messages.

## Requirements

To build crypt you must have:

- Gradle 7.12
- Java 17

installed on your system.

## Building

To build crypt from source run:

``` bash
gradle build
```

To create a new release run:

``` bash
gradle jar
```

The new release should be in `crypt/build/libs/crypt-${VERSION_MAJOR}-${VERSION_MINOR}-${VERSION_PATCH}.jar`

## Documentation

To build the documentation for the project run
``` bash
gradle javadoc
```

The documentation should be in `crypt/build/docs/javadoc/`

## Adding Toolbox to your build

### Gradle
To add a dependency using Gradle:

``` gradle
dependencies {
    implementation 'io.github.jmdaemon:crypt:0.1.0'
}
```

Note that since crypt isn't published on the `mavenCentral()` repositories, you must add
the following to your `settings.gradle` file:

```  gradle
sourceControl {
    gitRepository("https://github.com/jmdaemon/crypt.git") {
        producesModule('io.github.jmdaemon:crypt')
    }
}
```
