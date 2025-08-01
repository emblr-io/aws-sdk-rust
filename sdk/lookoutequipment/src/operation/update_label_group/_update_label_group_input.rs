// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLabelGroupInput {
    /// <p>The name of the label group to be updated.</p>
    pub label_group_name: ::std::option::Option<::std::string::String>,
    /// <p>Updates the code indicating the type of anomaly associated with the label.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fault_codes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UpdateLabelGroupInput {
    /// <p>The name of the label group to be updated.</p>
    pub fn label_group_name(&self) -> ::std::option::Option<&str> {
        self.label_group_name.as_deref()
    }
    /// <p>Updates the code indicating the type of anomaly associated with the label.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fault_codes.is_none()`.
    pub fn fault_codes(&self) -> &[::std::string::String] {
        self.fault_codes.as_deref().unwrap_or_default()
    }
}
impl UpdateLabelGroupInput {
    /// Creates a new builder-style object to manufacture [`UpdateLabelGroupInput`](crate::operation::update_label_group::UpdateLabelGroupInput).
    pub fn builder() -> crate::operation::update_label_group::builders::UpdateLabelGroupInputBuilder {
        crate::operation::update_label_group::builders::UpdateLabelGroupInputBuilder::default()
    }
}

/// A builder for [`UpdateLabelGroupInput`](crate::operation::update_label_group::UpdateLabelGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLabelGroupInputBuilder {
    pub(crate) label_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) fault_codes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UpdateLabelGroupInputBuilder {
    /// <p>The name of the label group to be updated.</p>
    /// This field is required.
    pub fn label_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.label_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the label group to be updated.</p>
    pub fn set_label_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.label_group_name = input;
        self
    }
    /// <p>The name of the label group to be updated.</p>
    pub fn get_label_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.label_group_name
    }
    /// Appends an item to `fault_codes`.
    ///
    /// To override the contents of this collection use [`set_fault_codes`](Self::set_fault_codes).
    ///
    /// <p>Updates the code indicating the type of anomaly associated with the label.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn fault_codes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.fault_codes.unwrap_or_default();
        v.push(input.into());
        self.fault_codes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Updates the code indicating the type of anomaly associated with the label.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn set_fault_codes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.fault_codes = input;
        self
    }
    /// <p>Updates the code indicating the type of anomaly associated with the label.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn get_fault_codes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.fault_codes
    }
    /// Consumes the builder and constructs a [`UpdateLabelGroupInput`](crate::operation::update_label_group::UpdateLabelGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_label_group::UpdateLabelGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_label_group::UpdateLabelGroupInput {
            label_group_name: self.label_group_name,
            fault_codes: self.fault_codes,
        })
    }
}
