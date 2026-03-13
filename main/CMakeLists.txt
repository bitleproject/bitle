idf_component_register(SRCS
    "main.c"
    "bitchat_ble.c"
    "noise_handshake.c"
    "packet_codec.c"
    "nickname_manager.c"
INCLUDE_DIRS "."
REQUIRES bt nvs_flash noise_ref mbedtls bitchat_utils
    )

target_include_directories(${COMPONENT_LIB} PRIVATE
    $ENV{IDF_PATH}/components/bt/host/nimble/nimble/nimble/include
    $ENV{IDF_PATH}/components/bt/host/nimble/nimble/nimble/host/include
    $ENV{IDF_PATH}/components/bt/host/nimble/nimble/porting/nimble/include
    $ENV{IDF_PATH}/components/bt/host/nimble/port/include
    $ENV{IDF_PATH}/components/bt/host/nimble/nimble/porting/npl/freertos/include
    $ENV{IDF_PATH}/components/bt/host/nimble/nimble/nimble/transport/include
    $ENV{IDF_PATH}/components/bt/host/nimble/esp-hci/include
)
