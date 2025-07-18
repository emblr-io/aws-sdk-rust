// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the status of an instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceStatusSummary {
    /// <p>The system instance health or application instance health.</p>
    pub details: ::std::option::Option<::std::vec::Vec<crate::types::InstanceStatusDetails>>,
    /// <p>The status.</p>
    pub status: ::std::option::Option<crate::types::SummaryStatus>,
}
impl InstanceStatusSummary {
    /// <p>The system instance health or application instance health.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.details.is_none()`.
    pub fn details(&self) -> &[crate::types::InstanceStatusDetails] {
        self.details.as_deref().unwrap_or_default()
    }
    /// <p>The status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SummaryStatus> {
        self.status.as_ref()
    }
}
impl InstanceStatusSummary {
    /// Creates a new builder-style object to manufacture [`InstanceStatusSummary`](crate::types::InstanceStatusSummary).
    pub fn builder() -> crate::types::builders::InstanceStatusSummaryBuilder {
        crate::types::builders::InstanceStatusSummaryBuilder::default()
    }
}

/// A builder for [`InstanceStatusSummary`](crate::types::InstanceStatusSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceStatusSummaryBuilder {
    pub(crate) details: ::std::option::Option<::std::vec::Vec<crate::types::InstanceStatusDetails>>,
    pub(crate) status: ::std::option::Option<crate::types::SummaryStatus>,
}
impl InstanceStatusSummaryBuilder {
    /// Appends an item to `details`.
    ///
    /// To override the contents of this collection use [`set_details`](Self::set_details).
    ///
    /// <p>The system instance health or application instance health.</p>
    pub fn details(mut self, input: crate::types::InstanceStatusDetails) -> Self {
        let mut v = self.details.unwrap_or_default();
        v.push(input);
        self.details = ::std::option::Option::Some(v);
        self
    }
    /// <p>The system instance health or application instance health.</p>
    pub fn set_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstanceStatusDetails>>) -> Self {
        self.details = input;
        self
    }
    /// <p>The system instance health or application instance health.</p>
    pub fn get_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstanceStatusDetails>> {
        &self.details
    }
    /// <p>The status.</p>
    pub fn status(mut self, input: crate::types::SummaryStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SummaryStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SummaryStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`InstanceStatusSummary`](crate::types::InstanceStatusSummary).
    pub fn build(self) -> crate::types::InstanceStatusSummary {
        crate::types::InstanceStatusSummary {
            details: self.details,
            status: self.status,
        }
    }
}
