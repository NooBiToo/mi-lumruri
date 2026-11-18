//! Общая библиотека mi-trusttunnel: модель, проверка, предпросмотр, хранение, формирование конфигурации и плана.
//! Здесь нет кода, меняющего сеть: его содержит только административный бинарник `mi-tt-admin`.

pub mod api;
pub mod model;
pub mod plan;
pub mod preview;
pub mod render;
pub mod store;
pub mod validate;
