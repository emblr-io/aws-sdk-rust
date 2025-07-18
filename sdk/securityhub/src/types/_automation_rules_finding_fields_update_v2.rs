// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Allows you to define the structure for modifying specific fields in security findings.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutomationRulesFindingFieldsUpdateV2 {
    /// <p>The severity level to be assigned to findings that match the automation rule criteria.</p>
    pub severity_id: ::std::option::Option<i32>,
    /// <p>Notes or contextual information for findings that are modified by the automation rule.</p>
    pub comment: ::std::option::Option<::std::string::String>,
    /// <p>The status to be applied to findings that match automation rule criteria.</p>
    pub status_id: ::std::option::Option<i32>,
}
impl AutomationRulesFindingFieldsUpdateV2 {
    /// <p>The severity level to be assigned to findings that match the automation rule criteria.</p>
    pub fn severity_id(&self) -> ::std::option::Option<i32> {
        self.severity_id
    }
    /// <p>Notes or contextual information for findings that are modified by the automation rule.</p>
    pub fn comment(&self) -> ::std::option::Option<&str> {
        self.comment.as_deref()
    }
    /// <p>The status to be applied to findings that match automation rule criteria.</p>
    pub fn status_id(&self) -> ::std::option::Option<i32> {
        self.status_id
    }
}
impl AutomationRulesFindingFieldsUpdateV2 {
    /// Creates a new builder-style object to manufacture [`AutomationRulesFindingFieldsUpdateV2`](crate::types::AutomationRulesFindingFieldsUpdateV2).
    pub fn builder() -> crate::types::builders::AutomationRulesFindingFieldsUpdateV2Builder {
        crate::types::builders::AutomationRulesFindingFieldsUpdateV2Builder::default()
    }
}

/// A builder for [`AutomationRulesFindingFieldsUpdateV2`](crate::types::AutomationRulesFindingFieldsUpdateV2).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutomationRulesFindingFieldsUpdateV2Builder {
    pub(crate) severity_id: ::std::option::Option<i32>,
    pub(crate) comment: ::std::option::Option<::std::string::String>,
    pub(crate) status_id: ::std::option::Option<i32>,
}
impl AutomationRulesFindingFieldsUpdateV2Builder {
    /// <p>The severity level to be assigned to findings that match the automation rule criteria.</p>
    pub fn severity_id(mut self, input: i32) -> Self {
        self.severity_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The severity level to be assigned to findings that match the automation rule criteria.</p>
    pub fn set_severity_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.severity_id = input;
        self
    }
    /// <p>The severity level to be assigned to findings that match the automation rule criteria.</p>
    pub fn get_severity_id(&self) -> &::std::option::Option<i32> {
        &self.severity_id
    }
    /// <p>Notes or contextual information for findings that are modified by the automation rule.</p>
    pub fn comment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.comment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Notes or contextual information for findings that are modified by the automation rule.</p>
    pub fn set_comment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.comment = input;
        self
    }
    /// <p>Notes or contextual information for findings that are modified by the automation rule.</p>
    pub fn get_comment(&self) -> &::std::option::Option<::std::string::String> {
        &self.comment
    }
    /// <p>The status to be applied to findings that match automation rule criteria.</p>
    pub fn status_id(mut self, input: i32) -> Self {
        self.status_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status to be applied to findings that match automation rule criteria.</p>
    pub fn set_status_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status_id = input;
        self
    }
    /// <p>The status to be applied to findings that match automation rule criteria.</p>
    pub fn get_status_id(&self) -> &::std::option::Option<i32> {
        &self.status_id
    }
    /// Consumes the builder and constructs a [`AutomationRulesFindingFieldsUpdateV2`](crate::types::AutomationRulesFindingFieldsUpdateV2).
    pub fn build(self) -> crate::types::AutomationRulesFindingFieldsUpdateV2 {
        crate::types::AutomationRulesFindingFieldsUpdateV2 {
            severity_id: self.severity_id,
            comment: self.comment,
            status_id: self.status_id,
        }
    }
}
