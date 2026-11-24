//! Общая библиотека Mi Lumruri: модель, проверка, предпросмотр, хранение, формирование конфигурации и плана.
//! Здесь нет кода, меняющего сеть: его содержит только административный бинарник `mi-tt-admin`.

pub mod api;
pub mod auth;
pub mod backup;
pub mod caps;
pub mod devices;
pub mod discover;
pub mod dns;
pub mod gate;
pub mod manage;
pub mod model;
pub mod notify;
pub mod plan;
pub mod preview;
pub mod proxy;
pub mod release;
pub mod render;
pub mod stats;
pub mod storage;
pub mod store;
pub mod subscription;
pub mod tunnel;
pub mod validate;
pub mod zapret;
