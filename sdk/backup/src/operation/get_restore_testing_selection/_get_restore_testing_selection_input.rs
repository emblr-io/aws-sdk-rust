// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRestoreTestingSelectionInput {
    /// <p>Required unique name of the restore testing plan.</p>
    pub restore_testing_plan_name: ::std::option::Option<::std::string::String>,
    /// <p>Required unique name of the restore testing selection.</p>
    pub restore_testing_selection_name: ::std::option::Option<::std::string::String>,
}
impl GetRestoreTestingSelectionInput {
    /// <p>Required unique name of the restore testing plan.</p>
    pub fn restore_testing_plan_name(&self) -> ::std::option::Option<&str> {
        self.restore_testing_plan_name.as_deref()
    }
    /// <p>Required unique name of the restore testing selection.</p>
    pub fn restore_testing_selection_name(&self) -> ::std::option::Option<&str> {
        self.restore_testing_selection_name.as_deref()
    }
}
impl GetRestoreTestingSelectionInput {
    /// Creates a new builder-style object to manufacture [`GetRestoreTestingSelectionInput`](crate::operation::get_restore_testing_selection::GetRestoreTestingSelectionInput).
    pub fn builder() -> crate::operation::get_restore_testing_selection::builders::GetRestoreTestingSelectionInputBuilder {
        crate::operation::get_restore_testing_selection::builders::GetRestoreTestingSelectionInputBuilder::default()
    }
}

/// A builder for [`GetRestoreTestingSelectionInput`](crate::operation::get_restore_testing_selection::GetRestoreTestingSelectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRestoreTestingSelectionInputBuilder {
    pub(crate) restore_testing_plan_name: ::std::option::Option<::std::string::String>,
    pub(crate) restore_testing_selection_name: ::std::option::Option<::std::string::String>,
}
impl GetRestoreTestingSelectionInputBuilder {
    /// <p>Required unique name of the restore testing plan.</p>
    /// This field is required.
    pub fn restore_testing_plan_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.restore_testing_plan_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required unique name of the restore testing plan.</p>
    pub fn set_restore_testing_plan_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.restore_testing_plan_name = input;
        self
    }
    /// <p>Required unique name of the restore testing plan.</p>
    pub fn get_restore_testing_plan_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.restore_testing_plan_name
    }
    /// <p>Required unique name of the restore testing selection.</p>
    /// This field is required.
    pub fn restore_testing_selection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.restore_testing_selection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required unique name of the restore testing selection.</p>
    pub fn set_restore_testing_selection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.restore_testing_selection_name = input;
        self
    }
    /// <p>Required unique name of the restore testing selection.</p>
    pub fn get_restore_testing_selection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.restore_testing_selection_name
    }
    /// Consumes the builder and constructs a [`GetRestoreTestingSelectionInput`](crate::operation::get_restore_testing_selection::GetRestoreTestingSelectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_restore_testing_selection::GetRestoreTestingSelectionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_restore_testing_selection::GetRestoreTestingSelectionInput {
            restore_testing_plan_name: self.restore_testing_plan_name,
            restore_testing_selection_name: self.restore_testing_selection_name,
        })
    }
}
