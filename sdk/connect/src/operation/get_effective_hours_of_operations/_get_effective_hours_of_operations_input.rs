// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEffectiveHoursOfOperationsInput {
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the hours of operation.</p>
    pub hours_of_operation_id: ::std::option::Option<::std::string::String>,
    /// <p>The Date from when the hours of operation are listed.</p>
    pub from_date: ::std::option::Option<::std::string::String>,
    /// <p>The Date until when the hours of operation are listed.</p>
    pub to_date: ::std::option::Option<::std::string::String>,
}
impl GetEffectiveHoursOfOperationsInput {
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier for the hours of operation.</p>
    pub fn hours_of_operation_id(&self) -> ::std::option::Option<&str> {
        self.hours_of_operation_id.as_deref()
    }
    /// <p>The Date from when the hours of operation are listed.</p>
    pub fn from_date(&self) -> ::std::option::Option<&str> {
        self.from_date.as_deref()
    }
    /// <p>The Date until when the hours of operation are listed.</p>
    pub fn to_date(&self) -> ::std::option::Option<&str> {
        self.to_date.as_deref()
    }
}
impl GetEffectiveHoursOfOperationsInput {
    /// Creates a new builder-style object to manufacture [`GetEffectiveHoursOfOperationsInput`](crate::operation::get_effective_hours_of_operations::GetEffectiveHoursOfOperationsInput).
    pub fn builder() -> crate::operation::get_effective_hours_of_operations::builders::GetEffectiveHoursOfOperationsInputBuilder {
        crate::operation::get_effective_hours_of_operations::builders::GetEffectiveHoursOfOperationsInputBuilder::default()
    }
}

/// A builder for [`GetEffectiveHoursOfOperationsInput`](crate::operation::get_effective_hours_of_operations::GetEffectiveHoursOfOperationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEffectiveHoursOfOperationsInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) hours_of_operation_id: ::std::option::Option<::std::string::String>,
    pub(crate) from_date: ::std::option::Option<::std::string::String>,
    pub(crate) to_date: ::std::option::Option<::std::string::String>,
}
impl GetEffectiveHoursOfOperationsInputBuilder {
    /// <p>The identifier of the Amazon Connect instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The identifier for the hours of operation.</p>
    /// This field is required.
    pub fn hours_of_operation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hours_of_operation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the hours of operation.</p>
    pub fn set_hours_of_operation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hours_of_operation_id = input;
        self
    }
    /// <p>The identifier for the hours of operation.</p>
    pub fn get_hours_of_operation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hours_of_operation_id
    }
    /// <p>The Date from when the hours of operation are listed.</p>
    /// This field is required.
    pub fn from_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.from_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Date from when the hours of operation are listed.</p>
    pub fn set_from_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.from_date = input;
        self
    }
    /// <p>The Date from when the hours of operation are listed.</p>
    pub fn get_from_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.from_date
    }
    /// <p>The Date until when the hours of operation are listed.</p>
    /// This field is required.
    pub fn to_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.to_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Date until when the hours of operation are listed.</p>
    pub fn set_to_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.to_date = input;
        self
    }
    /// <p>The Date until when the hours of operation are listed.</p>
    pub fn get_to_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.to_date
    }
    /// Consumes the builder and constructs a [`GetEffectiveHoursOfOperationsInput`](crate::operation::get_effective_hours_of_operations::GetEffectiveHoursOfOperationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_effective_hours_of_operations::GetEffectiveHoursOfOperationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_effective_hours_of_operations::GetEffectiveHoursOfOperationsInput {
            instance_id: self.instance_id,
            hours_of_operation_id: self.hours_of_operation_id,
            from_date: self.from_date,
            to_date: self.to_date,
        })
    }
}
