// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A cluster of similar anomalous log events found within a log group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogAnomalyShowcase {
    /// <p>A list of anomalous log events that may be related.</p>
    pub log_anomaly_classes: ::std::option::Option<::std::vec::Vec<crate::types::LogAnomalyClass>>,
}
impl LogAnomalyShowcase {
    /// <p>A list of anomalous log events that may be related.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_anomaly_classes.is_none()`.
    pub fn log_anomaly_classes(&self) -> &[crate::types::LogAnomalyClass] {
        self.log_anomaly_classes.as_deref().unwrap_or_default()
    }
}
impl LogAnomalyShowcase {
    /// Creates a new builder-style object to manufacture [`LogAnomalyShowcase`](crate::types::LogAnomalyShowcase).
    pub fn builder() -> crate::types::builders::LogAnomalyShowcaseBuilder {
        crate::types::builders::LogAnomalyShowcaseBuilder::default()
    }
}

/// A builder for [`LogAnomalyShowcase`](crate::types::LogAnomalyShowcase).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LogAnomalyShowcaseBuilder {
    pub(crate) log_anomaly_classes: ::std::option::Option<::std::vec::Vec<crate::types::LogAnomalyClass>>,
}
impl LogAnomalyShowcaseBuilder {
    /// Appends an item to `log_anomaly_classes`.
    ///
    /// To override the contents of this collection use [`set_log_anomaly_classes`](Self::set_log_anomaly_classes).
    ///
    /// <p>A list of anomalous log events that may be related.</p>
    pub fn log_anomaly_classes(mut self, input: crate::types::LogAnomalyClass) -> Self {
        let mut v = self.log_anomaly_classes.unwrap_or_default();
        v.push(input);
        self.log_anomaly_classes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of anomalous log events that may be related.</p>
    pub fn set_log_anomaly_classes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LogAnomalyClass>>) -> Self {
        self.log_anomaly_classes = input;
        self
    }
    /// <p>A list of anomalous log events that may be related.</p>
    pub fn get_log_anomaly_classes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LogAnomalyClass>> {
        &self.log_anomaly_classes
    }
    /// Consumes the builder and constructs a [`LogAnomalyShowcase`](crate::types::LogAnomalyShowcase).
    pub fn build(self) -> crate::types::LogAnomalyShowcase {
        crate::types::LogAnomalyShowcase {
            log_anomaly_classes: self.log_anomaly_classes,
        }
    }
}
