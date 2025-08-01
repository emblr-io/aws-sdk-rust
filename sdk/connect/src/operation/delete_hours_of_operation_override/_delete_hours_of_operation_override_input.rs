// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteHoursOfOperationOverrideInput {
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the hours of operation.</p>
    pub hours_of_operation_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the hours of operation override.</p>
    pub hours_of_operation_override_id: ::std::option::Option<::std::string::String>,
}
impl DeleteHoursOfOperationOverrideInput {
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier for the hours of operation.</p>
    pub fn hours_of_operation_id(&self) -> ::std::option::Option<&str> {
        self.hours_of_operation_id.as_deref()
    }
    /// <p>The identifier for the hours of operation override.</p>
    pub fn hours_of_operation_override_id(&self) -> ::std::option::Option<&str> {
        self.hours_of_operation_override_id.as_deref()
    }
}
impl DeleteHoursOfOperationOverrideInput {
    /// Creates a new builder-style object to manufacture [`DeleteHoursOfOperationOverrideInput`](crate::operation::delete_hours_of_operation_override::DeleteHoursOfOperationOverrideInput).
    pub fn builder() -> crate::operation::delete_hours_of_operation_override::builders::DeleteHoursOfOperationOverrideInputBuilder {
        crate::operation::delete_hours_of_operation_override::builders::DeleteHoursOfOperationOverrideInputBuilder::default()
    }
}

/// A builder for [`DeleteHoursOfOperationOverrideInput`](crate::operation::delete_hours_of_operation_override::DeleteHoursOfOperationOverrideInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteHoursOfOperationOverrideInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) hours_of_operation_id: ::std::option::Option<::std::string::String>,
    pub(crate) hours_of_operation_override_id: ::std::option::Option<::std::string::String>,
}
impl DeleteHoursOfOperationOverrideInputBuilder {
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
    /// <p>The identifier for the hours of operation override.</p>
    /// This field is required.
    pub fn hours_of_operation_override_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hours_of_operation_override_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the hours of operation override.</p>
    pub fn set_hours_of_operation_override_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hours_of_operation_override_id = input;
        self
    }
    /// <p>The identifier for the hours of operation override.</p>
    pub fn get_hours_of_operation_override_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hours_of_operation_override_id
    }
    /// Consumes the builder and constructs a [`DeleteHoursOfOperationOverrideInput`](crate::operation::delete_hours_of_operation_override::DeleteHoursOfOperationOverrideInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_hours_of_operation_override::DeleteHoursOfOperationOverrideInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_hours_of_operation_override::DeleteHoursOfOperationOverrideInput {
                instance_id: self.instance_id,
                hours_of_operation_id: self.hours_of_operation_id,
                hours_of_operation_override_id: self.hours_of_operation_override_id,
            },
        )
    }
}
