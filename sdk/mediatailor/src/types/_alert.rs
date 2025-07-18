// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Alert configuration parameters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Alert {
    /// <p>The code for the alert. For example, <code>NOT_PROCESSED</code>.</p>
    pub alert_code: ::std::string::String,
    /// <p>If an alert is generated for a resource, an explanation of the reason for the alert.</p>
    pub alert_message: ::std::string::String,
    /// <p>The timestamp when the alert was last modified.</p>
    pub last_modified_time: ::aws_smithy_types::DateTime,
    /// <p>The Amazon Resource Names (ARNs) related to this alert.</p>
    pub related_resource_arns: ::std::vec::Vec<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub resource_arn: ::std::string::String,
    /// <p>The category that MediaTailor assigns to the alert.</p>
    pub category: ::std::option::Option<crate::types::AlertCategory>,
}
impl Alert {
    /// <p>The code for the alert. For example, <code>NOT_PROCESSED</code>.</p>
    pub fn alert_code(&self) -> &str {
        use std::ops::Deref;
        self.alert_code.deref()
    }
    /// <p>If an alert is generated for a resource, an explanation of the reason for the alert.</p>
    pub fn alert_message(&self) -> &str {
        use std::ops::Deref;
        self.alert_message.deref()
    }
    /// <p>The timestamp when the alert was last modified.</p>
    pub fn last_modified_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_modified_time
    }
    /// <p>The Amazon Resource Names (ARNs) related to this alert.</p>
    pub fn related_resource_arns(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.related_resource_arns.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn resource_arn(&self) -> &str {
        use std::ops::Deref;
        self.resource_arn.deref()
    }
    /// <p>The category that MediaTailor assigns to the alert.</p>
    pub fn category(&self) -> ::std::option::Option<&crate::types::AlertCategory> {
        self.category.as_ref()
    }
}
impl Alert {
    /// Creates a new builder-style object to manufacture [`Alert`](crate::types::Alert).
    pub fn builder() -> crate::types::builders::AlertBuilder {
        crate::types::builders::AlertBuilder::default()
    }
}

/// A builder for [`Alert`](crate::types::Alert).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AlertBuilder {
    pub(crate) alert_code: ::std::option::Option<::std::string::String>,
    pub(crate) alert_message: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) related_resource_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) category: ::std::option::Option<crate::types::AlertCategory>,
}
impl AlertBuilder {
    /// <p>The code for the alert. For example, <code>NOT_PROCESSED</code>.</p>
    /// This field is required.
    pub fn alert_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alert_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The code for the alert. For example, <code>NOT_PROCESSED</code>.</p>
    pub fn set_alert_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alert_code = input;
        self
    }
    /// <p>The code for the alert. For example, <code>NOT_PROCESSED</code>.</p>
    pub fn get_alert_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.alert_code
    }
    /// <p>If an alert is generated for a resource, an explanation of the reason for the alert.</p>
    /// This field is required.
    pub fn alert_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alert_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If an alert is generated for a resource, an explanation of the reason for the alert.</p>
    pub fn set_alert_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alert_message = input;
        self
    }
    /// <p>If an alert is generated for a resource, an explanation of the reason for the alert.</p>
    pub fn get_alert_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.alert_message
    }
    /// <p>The timestamp when the alert was last modified.</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the alert was last modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp when the alert was last modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// Appends an item to `related_resource_arns`.
    ///
    /// To override the contents of this collection use [`set_related_resource_arns`](Self::set_related_resource_arns).
    ///
    /// <p>The Amazon Resource Names (ARNs) related to this alert.</p>
    pub fn related_resource_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.related_resource_arns.unwrap_or_default();
        v.push(input.into());
        self.related_resource_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Names (ARNs) related to this alert.</p>
    pub fn set_related_resource_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.related_resource_arns = input;
        self
    }
    /// <p>The Amazon Resource Names (ARNs) related to this alert.</p>
    pub fn get_related_resource_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.related_resource_arns
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The category that MediaTailor assigns to the alert.</p>
    pub fn category(mut self, input: crate::types::AlertCategory) -> Self {
        self.category = ::std::option::Option::Some(input);
        self
    }
    /// <p>The category that MediaTailor assigns to the alert.</p>
    pub fn set_category(mut self, input: ::std::option::Option<crate::types::AlertCategory>) -> Self {
        self.category = input;
        self
    }
    /// <p>The category that MediaTailor assigns to the alert.</p>
    pub fn get_category(&self) -> &::std::option::Option<crate::types::AlertCategory> {
        &self.category
    }
    /// Consumes the builder and constructs a [`Alert`](crate::types::Alert).
    /// This method will fail if any of the following fields are not set:
    /// - [`alert_code`](crate::types::builders::AlertBuilder::alert_code)
    /// - [`alert_message`](crate::types::builders::AlertBuilder::alert_message)
    /// - [`last_modified_time`](crate::types::builders::AlertBuilder::last_modified_time)
    /// - [`related_resource_arns`](crate::types::builders::AlertBuilder::related_resource_arns)
    /// - [`resource_arn`](crate::types::builders::AlertBuilder::resource_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::Alert, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Alert {
            alert_code: self.alert_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "alert_code",
                    "alert_code was not specified but it is required when building Alert",
                )
            })?,
            alert_message: self.alert_message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "alert_message",
                    "alert_message was not specified but it is required when building Alert",
                )
            })?,
            last_modified_time: self.last_modified_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_time",
                    "last_modified_time was not specified but it is required when building Alert",
                )
            })?,
            related_resource_arns: self.related_resource_arns.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "related_resource_arns",
                    "related_resource_arns was not specified but it is required when building Alert",
                )
            })?,
            resource_arn: self.resource_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_arn",
                    "resource_arn was not specified but it is required when building Alert",
                )
            })?,
            category: self.category,
        })
    }
}
