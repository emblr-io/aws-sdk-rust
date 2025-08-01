// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the CloudWatch alarm specification to use in an instance refresh.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AlarmSpecification {
    /// <p>The names of one or more CloudWatch alarms to monitor for the instance refresh. You can specify up to 10 alarms.</p>
    pub alarms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AlarmSpecification {
    /// <p>The names of one or more CloudWatch alarms to monitor for the instance refresh. You can specify up to 10 alarms.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.alarms.is_none()`.
    pub fn alarms(&self) -> &[::std::string::String] {
        self.alarms.as_deref().unwrap_or_default()
    }
}
impl AlarmSpecification {
    /// Creates a new builder-style object to manufacture [`AlarmSpecification`](crate::types::AlarmSpecification).
    pub fn builder() -> crate::types::builders::AlarmSpecificationBuilder {
        crate::types::builders::AlarmSpecificationBuilder::default()
    }
}

/// A builder for [`AlarmSpecification`](crate::types::AlarmSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AlarmSpecificationBuilder {
    pub(crate) alarms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AlarmSpecificationBuilder {
    /// Appends an item to `alarms`.
    ///
    /// To override the contents of this collection use [`set_alarms`](Self::set_alarms).
    ///
    /// <p>The names of one or more CloudWatch alarms to monitor for the instance refresh. You can specify up to 10 alarms.</p>
    pub fn alarms(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.alarms.unwrap_or_default();
        v.push(input.into());
        self.alarms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of one or more CloudWatch alarms to monitor for the instance refresh. You can specify up to 10 alarms.</p>
    pub fn set_alarms(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.alarms = input;
        self
    }
    /// <p>The names of one or more CloudWatch alarms to monitor for the instance refresh. You can specify up to 10 alarms.</p>
    pub fn get_alarms(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.alarms
    }
    /// Consumes the builder and constructs a [`AlarmSpecification`](crate::types::AlarmSpecification).
    pub fn build(self) -> crate::types::AlarmSpecification {
        crate::types::AlarmSpecification { alarms: self.alarms }
    }
}
