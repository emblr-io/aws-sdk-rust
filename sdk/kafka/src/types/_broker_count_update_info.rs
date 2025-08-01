// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information regarding UpdateBrokerCount.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BrokerCountUpdateInfo {
    /// <p>Kafka Broker IDs of brokers being created.</p>
    pub created_broker_ids: ::std::option::Option<::std::vec::Vec<f64>>,
    /// <p>Kafka Broker IDs of brokers being deleted.</p>
    pub deleted_broker_ids: ::std::option::Option<::std::vec::Vec<f64>>,
}
impl BrokerCountUpdateInfo {
    /// <p>Kafka Broker IDs of brokers being created.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.created_broker_ids.is_none()`.
    pub fn created_broker_ids(&self) -> &[f64] {
        self.created_broker_ids.as_deref().unwrap_or_default()
    }
    /// <p>Kafka Broker IDs of brokers being deleted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.deleted_broker_ids.is_none()`.
    pub fn deleted_broker_ids(&self) -> &[f64] {
        self.deleted_broker_ids.as_deref().unwrap_or_default()
    }
}
impl BrokerCountUpdateInfo {
    /// Creates a new builder-style object to manufacture [`BrokerCountUpdateInfo`](crate::types::BrokerCountUpdateInfo).
    pub fn builder() -> crate::types::builders::BrokerCountUpdateInfoBuilder {
        crate::types::builders::BrokerCountUpdateInfoBuilder::default()
    }
}

/// A builder for [`BrokerCountUpdateInfo`](crate::types::BrokerCountUpdateInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BrokerCountUpdateInfoBuilder {
    pub(crate) created_broker_ids: ::std::option::Option<::std::vec::Vec<f64>>,
    pub(crate) deleted_broker_ids: ::std::option::Option<::std::vec::Vec<f64>>,
}
impl BrokerCountUpdateInfoBuilder {
    /// Appends an item to `created_broker_ids`.
    ///
    /// To override the contents of this collection use [`set_created_broker_ids`](Self::set_created_broker_ids).
    ///
    /// <p>Kafka Broker IDs of brokers being created.</p>
    pub fn created_broker_ids(mut self, input: f64) -> Self {
        let mut v = self.created_broker_ids.unwrap_or_default();
        v.push(input);
        self.created_broker_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Kafka Broker IDs of brokers being created.</p>
    pub fn set_created_broker_ids(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.created_broker_ids = input;
        self
    }
    /// <p>Kafka Broker IDs of brokers being created.</p>
    pub fn get_created_broker_ids(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.created_broker_ids
    }
    /// Appends an item to `deleted_broker_ids`.
    ///
    /// To override the contents of this collection use [`set_deleted_broker_ids`](Self::set_deleted_broker_ids).
    ///
    /// <p>Kafka Broker IDs of brokers being deleted.</p>
    pub fn deleted_broker_ids(mut self, input: f64) -> Self {
        let mut v = self.deleted_broker_ids.unwrap_or_default();
        v.push(input);
        self.deleted_broker_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Kafka Broker IDs of brokers being deleted.</p>
    pub fn set_deleted_broker_ids(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.deleted_broker_ids = input;
        self
    }
    /// <p>Kafka Broker IDs of brokers being deleted.</p>
    pub fn get_deleted_broker_ids(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.deleted_broker_ids
    }
    /// Consumes the builder and constructs a [`BrokerCountUpdateInfo`](crate::types::BrokerCountUpdateInfo).
    pub fn build(self) -> crate::types::BrokerCountUpdateInfo {
        crate::types::BrokerCountUpdateInfo {
            created_broker_ids: self.created_broker_ids,
            deleted_broker_ids: self.deleted_broker_ids,
        }
    }
}
