# How to Convert Mosquitto Client Code to MasQiTT Code

This document describes how to convert a client that uses the
Mosquitto library into using the MasQiTT library. That is, a
subscriber and/or a publisher that uses the Mosquitto library now
wants to take advantage of the MasQiTT library for cryptography on top
of Mosquitto.

## Example Publisher

The code in this example comes from Mosquitto 2.0.15 and can be
located at `mosquitto-2.0.15/examples/publish/basic-1.c`.

The final code after conversion can be found at
`examples/masqitt_publisher.c`

* Initialization:
    * Setup a Key Management Server (KMS) and know its hostname and port
    * Include the MasqiTT library: `#include <masqitt.h>`
    * Replace `struct mosquitto` with `struct masqitt`
    * Remove `mosquitto_lib_init()` and `mosquitto_lib_clean()`. These
      are no longer necessary, as MasQiTT does these internally when a
      `struct masqitt` is initialized through the use of `MASQ_new()`.
    * Replace `mosquitto_new()` with `MASQ_new()` to initialize a
      `struct masqitt`. A pointer to the initialized `struct masqitt`
      is returned in the same way that `mosquitto_new()` was
      used. Note that several additional parameters will be
      needed. See `masqitt.h` for details.
        * MasQiTT (MASQ) client ID
        * Mosquitto (MQTT) Client ID
        * MASQ role (i.e., publisher, subscriber, both)
        * Publisher strategy (e.g., MEK encapsulation strategy or EPH keys)
        * Publisher strategy value (e.g., threshold for generating a new MEK)
        * KMS host name
        * KMS host port
* Usage (Callbacks and Publishing):
    * If MasQiTT does not provide a function in its API but Mosquitto
      does, and you would like to use it, there is a way to do so. The
      function `MASQ_get_mosquitto()` can be used to retrieve the
      internal `struct mosquitto *`. This returns a pointer to the
      internal `struct mosquitto`, NOT a copy, so do NOT free this
      pointer. With this pointer, the normal Mosquitto API can be
      used. Do not use both the Mosquitto API for functions that
      MasQiTT provides, such as publishing, otherwise you will not be
      using the secure methods for MQTT.
        * A good example of when to use `MASQ_get_mosquitto()` is for
          using the callback setters EXCEPT for the message callback
          setter. That is, if the function
          `mosquitto_connect_callback_set()` is desired, then use
          `MASQ_get_mosquitto()` to retrieve the `struct mosquitto *`
          and then call `mosquitto_connect_callback_set()` with the
          retrieved `struct mosquitto *` as a parameter.
    * Replace the message callback setter
      `mosquitto_message_callback_set()` with `
      MASQ_message_v5_callback_set()`.
        * Note that since MasQiTT requires using MQTTv5, some
          functions such as the callback provided to
          `MASQ_message_v5_callback_set()` will require the additional
          `mosquitto_property *` parameter, or a compiler warning may
          occur. Also note that the body of the callback function does
          not require any changes unless there is interest in
          utilizing the MQTTv5 functionality of the Mosquitto
          properties.
    * Replace uses of `mosquitto_publish()` with
      `MASQ_publish_v5()`. Note that the only difference in this API
      is that the parameter `struct mosquitto *` is not for a `struct
      masqitt *`. The other parameters are the same as a MQTTv5
      publish function. If this is replacing `mosquitto_publish()`
      instead of `mosquitto_publish_v5()` then an additional parameter
      to a `mosquitto_property *` is needed (but can be `NULL` if no
      properties need to be provided). This change is not because of a
      MasQiTT requirement, but an MQTTv5 protocol requirement,
      although MasQiTT does require MQTTv5.
        * The return value of `MASQ_publish_v5()` is a `MASQ_status_t`
          status enum instead of the `int` return code that Mosquitto
          uses. Success is indicated by the value
          `MASQ_STATUS_SUCCESS`. A status can be converted to a string
          with the helper function `MASQ_status_to_str()` if the
          header `api.h` is included.
* Cleanup:
    * Although not necessary, it is probably good practice to set the
      local variable retrieved from `MASQ_get_mosquitto()` to NULL.
    * Be sure to call `MASQ_destroy()` to clean up all instantiations
      of `struct masqitt`.
* Compilation:
    * The compile and link step may vary based on the machine's
      environment variables and where shared libraries are located.
    * These steps should work without assumptions of the setup:
        * Compile with `-I` flags to indicate paths to headers that
          will be included:
            * `-I<path to masqitt.h>`
            * `-I<path to mosquitto.h>`
        * Compile with `-L` flags to indicate paths to libraries that
          will be linked (pairs with `-l` flag):
            * `-L<path to libmasqitt.so>`
            * `-L<path to libmosquitto.so>`
        * Compile with `-l` flags to indicate static libraries that
          will be linked (pairs with `-L` flag):
            * `-lmasqitt`
            * `-lmosquitto`
            * `-lcrypto`
* Runtime:
    * It will likely be necessary to also update the `LD_LIBRARY_PATH`
      environment variable to include paths to `libmasqitt.so` and
      `libmosquitto.so`, similar to the compile step above with the
      `-L` flag.

## Example Subscriber

The code in this example comes from Mosquitto 2.0.15 and can be
located at `mosquitto-2.0.15/examples/subscribe/basic-1.c`.

The final code after conversion can be found at
`examples/masqitt_subscriber.c`

* Initialization:
    * Setup a Key Management Server (KMS) and know its hostname and port
    * Include the MasqiTT library: `#include <masqitt.h>`
    * Replace `struct mosquitto` with `struct masqitt`
    * Remove `mosquitto_lib_init()` and `mosquitto_lib_clean()`. These
      are no longer necessary, as MasQiTT does these internally when a
      `struct masqitt` is initialized through the use of `MASQ_new()`.
    * Replace `mosquitto_new()` with `MASQ_new()` to initialize a
      `struct masqitt`. A pointer to the initialized `struct masqitt`
      is returned in the same way that `mosquitto_new()` was
      used. Note that several additional parameters will be
      needed. See `masqitt.h` for details.
        * MasQiTT (MASQ) client ID
        * Mosquitto (MQTT) Client ID
        * MASQ role (i.e., publisher, subscriber, both)
        * Publisher strategy (e.g., MEK encapsulation strategy or EPH keys)
        * Publisher strategy value (e.g., threshold for generating a new MEK)
        * KMS host name
        * KMS host port
* Usage (Callbacks and Subscribing):
    * If MasQiTT does not provide a function in its API but Mosquitto
      does, and you would like to use it, there is a way to do so. The
      function `MASQ_get_mosquitto()` can be used to retrieve the
      internal `struct mosquitto *`. This returns a pointer to the
      internal `struct mosquitto`, NOT a copy, so do NOT free this
      pointer. With this pointer, the normal Mosquitto API can be
      used. Do not use both the Mosquitto API for functions that
      MasQiTT provides, such as publishing, otherwise you will not be
      using the secure methods for MQTT.
        * A good example of when to use `MASQ_get_mosquitto()` is for
          using the callback setters EXCEPT for the message callback
          setter. That is, if the function
          `mosquitto_connect_callback_set()` is desired, then use
          `MASQ_get_mosquitto()` to retrieve the `struct mosquitto *`
          and then call `mosquitto_connect_callback_set()` with the
          retrieved `struct mosquitto *` as a parameter.
    * Replace the message callback setter `mosquitto_message_callback_set()`
      with ` MASQ_message_v5_callback_set()`.
        * Note that since MasQiTT requires using MQTTv5, some
          functions such as the callback provided to
          `MASQ_message_v5_callback_set()` will require the additional
          `mosquitto_property *` parameter, or a compiler warning may
          occur. Also note that the body of the callback function does
          not require any changes unless there is interest in
          utilizing the MQTTv5 functionality of the Mosquitto
          properties.
    * No special MASQ API function is needed for subscribing. The
      Mosquitto subscribe can be used as before.
* Cleanup:
    * Although not necessary, it is probably good practice to set the
      local variable retrieved from `MASQ_get_mosquitto()` to NULL.
    * Be sure to call `MASQ_destroy()` to clean up all instantiations
      of `struct masqitt`.
* Compilation:
    * The compile and link step may vary based on the machine's
      environment variables and where shared libraries are located.
    * These steps should work without assumptions of the setup:
        * Compile with `-I` flags to indicate paths to headers that
          will be included:
            * `-I<path to masqitt.h>`
            * `-I<path to mosquitto.h>`
        * Compile with `-L` flags to indicate paths to libraries that
          will be linked (pairs with `-l` flag):
            * `-L<path to libmasqitt.so>`
            * `-L<path to libmosquitto.so>`
        * Compile with `-l` flags to indicate static libraries that
          will be linked (pairs with `-L` flag):
            * `-lmasqitt`
            * `-lmosquitto`
            * `-lcrypto`
* Runtime:
    * It will likely be necessary to also update the `LD_LIBRARY_PATH`
      environment variable to include paths to `libmasqitt.so` and
      `libmosquitto.so`, similar to the compile step above with the
      `-L` flag. Running `sudo make install` on both the Mosquitto and
      MasQiTT source will copy both libraries to `/usr/local/lib`.
