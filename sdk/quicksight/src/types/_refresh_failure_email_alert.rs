// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration settings for the email alerts that are sent when a dataset refresh fails.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RefreshFailureEmailAlert {
    /// <p>The status value that determines if email alerts are sent.</p>
    pub alert_status: ::std::option::Option<crate::types::RefreshFailureAlertStatus>,
}
impl RefreshFailureEmailAlert {
    /// <p>The status value that determines if email alerts are sent.</p>
    pub fn alert_status(&self) -> ::std::option::Option<&crate::types::RefreshFailureAlertStatus> {
        self.alert_status.as_ref()
    }
}
impl RefreshFailureEmailAlert {
    /// Creates a new builder-style object to manufacture [`RefreshFailureEmailAlert`](crate::types::RefreshFailureEmailAlert).
    pub fn builder() -> crate::types::builders::RefreshFailureEmailAlertBuilder {
        crate::types::builders::RefreshFailureEmailAlertBuilder::default()
    }
}

/// A builder for [`RefreshFailureEmailAlert`](crate::types::RefreshFailureEmailAlert).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RefreshFailureEmailAlertBuilder {
    pub(crate) alert_status: ::std::option::Option<crate::types::RefreshFailureAlertStatus>,
}
impl RefreshFailureEmailAlertBuilder {
    /// <p>The status value that determines if email alerts are sent.</p>
    pub fn alert_status(mut self, input: crate::types::RefreshFailureAlertStatus) -> Self {
        self.alert_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status value that determines if email alerts are sent.</p>
    pub fn set_alert_status(mut self, input: ::std::option::Option<crate::types::RefreshFailureAlertStatus>) -> Self {
        self.alert_status = input;
        self
    }
    /// <p>The status value that determines if email alerts are sent.</p>
    pub fn get_alert_status(&self) -> &::std::option::Option<crate::types::RefreshFailureAlertStatus> {
        &self.alert_status
    }
    /// Consumes the builder and constructs a [`RefreshFailureEmailAlert`](crate::types::RefreshFailureEmailAlert).
    pub fn build(self) -> crate::types::RefreshFailureEmailAlert {
        crate::types::RefreshFailureEmailAlert {
            alert_status: self.alert_status,
        }
    }
}
