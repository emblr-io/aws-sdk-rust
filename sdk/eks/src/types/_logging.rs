// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing the logging configuration for resources in your cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Logging {
    /// <p>The cluster control plane logging configuration for your cluster.</p>
    pub cluster_logging: ::std::option::Option<::std::vec::Vec<crate::types::LogSetup>>,
}
impl Logging {
    /// <p>The cluster control plane logging configuration for your cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cluster_logging.is_none()`.
    pub fn cluster_logging(&self) -> &[crate::types::LogSetup] {
        self.cluster_logging.as_deref().unwrap_or_default()
    }
}
impl Logging {
    /// Creates a new builder-style object to manufacture [`Logging`](crate::types::Logging).
    pub fn builder() -> crate::types::builders::LoggingBuilder {
        crate::types::builders::LoggingBuilder::default()
    }
}

/// A builder for [`Logging`](crate::types::Logging).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LoggingBuilder {
    pub(crate) cluster_logging: ::std::option::Option<::std::vec::Vec<crate::types::LogSetup>>,
}
impl LoggingBuilder {
    /// Appends an item to `cluster_logging`.
    ///
    /// To override the contents of this collection use [`set_cluster_logging`](Self::set_cluster_logging).
    ///
    /// <p>The cluster control plane logging configuration for your cluster.</p>
    pub fn cluster_logging(mut self, input: crate::types::LogSetup) -> Self {
        let mut v = self.cluster_logging.unwrap_or_default();
        v.push(input);
        self.cluster_logging = ::std::option::Option::Some(v);
        self
    }
    /// <p>The cluster control plane logging configuration for your cluster.</p>
    pub fn set_cluster_logging(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LogSetup>>) -> Self {
        self.cluster_logging = input;
        self
    }
    /// <p>The cluster control plane logging configuration for your cluster.</p>
    pub fn get_cluster_logging(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LogSetup>> {
        &self.cluster_logging
    }
    /// Consumes the builder and constructs a [`Logging`](crate::types::Logging).
    pub fn build(self) -> crate::types::Logging {
        crate::types::Logging {
            cluster_logging: self.cluster_logging,
        }
    }
}
