// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the rule settings for when messages can't be sent.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClosedDaysRule {
    /// <p>The name of the closed day rule.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Start DateTime ISO 8601 format</p>
    pub start_date_time: ::std::option::Option<::std::string::String>,
    /// <p>End DateTime ISO 8601 format</p>
    pub end_date_time: ::std::option::Option<::std::string::String>,
}
impl ClosedDaysRule {
    /// <p>The name of the closed day rule.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Start DateTime ISO 8601 format</p>
    pub fn start_date_time(&self) -> ::std::option::Option<&str> {
        self.start_date_time.as_deref()
    }
    /// <p>End DateTime ISO 8601 format</p>
    pub fn end_date_time(&self) -> ::std::option::Option<&str> {
        self.end_date_time.as_deref()
    }
}
impl ClosedDaysRule {
    /// Creates a new builder-style object to manufacture [`ClosedDaysRule`](crate::types::ClosedDaysRule).
    pub fn builder() -> crate::types::builders::ClosedDaysRuleBuilder {
        crate::types::builders::ClosedDaysRuleBuilder::default()
    }
}

/// A builder for [`ClosedDaysRule`](crate::types::ClosedDaysRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClosedDaysRuleBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) start_date_time: ::std::option::Option<::std::string::String>,
    pub(crate) end_date_time: ::std::option::Option<::std::string::String>,
}
impl ClosedDaysRuleBuilder {
    /// <p>The name of the closed day rule.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the closed day rule.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the closed day rule.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Start DateTime ISO 8601 format</p>
    pub fn start_date_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_date_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Start DateTime ISO 8601 format</p>
    pub fn set_start_date_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_date_time = input;
        self
    }
    /// <p>Start DateTime ISO 8601 format</p>
    pub fn get_start_date_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_date_time
    }
    /// <p>End DateTime ISO 8601 format</p>
    pub fn end_date_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.end_date_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>End DateTime ISO 8601 format</p>
    pub fn set_end_date_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.end_date_time = input;
        self
    }
    /// <p>End DateTime ISO 8601 format</p>
    pub fn get_end_date_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.end_date_time
    }
    /// Consumes the builder and constructs a [`ClosedDaysRule`](crate::types::ClosedDaysRule).
    pub fn build(self) -> crate::types::ClosedDaysRule {
        crate::types::ClosedDaysRule {
            name: self.name,
            start_date_time: self.start_date_time,
            end_date_time: self.end_date_time,
        }
    }
}
