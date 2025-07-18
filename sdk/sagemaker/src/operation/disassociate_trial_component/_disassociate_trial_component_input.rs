// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateTrialComponentInput {
    /// <p>The name of the component to disassociate from the trial.</p>
    pub trial_component_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the trial to disassociate from.</p>
    pub trial_name: ::std::option::Option<::std::string::String>,
}
impl DisassociateTrialComponentInput {
    /// <p>The name of the component to disassociate from the trial.</p>
    pub fn trial_component_name(&self) -> ::std::option::Option<&str> {
        self.trial_component_name.as_deref()
    }
    /// <p>The name of the trial to disassociate from.</p>
    pub fn trial_name(&self) -> ::std::option::Option<&str> {
        self.trial_name.as_deref()
    }
}
impl DisassociateTrialComponentInput {
    /// Creates a new builder-style object to manufacture [`DisassociateTrialComponentInput`](crate::operation::disassociate_trial_component::DisassociateTrialComponentInput).
    pub fn builder() -> crate::operation::disassociate_trial_component::builders::DisassociateTrialComponentInputBuilder {
        crate::operation::disassociate_trial_component::builders::DisassociateTrialComponentInputBuilder::default()
    }
}

/// A builder for [`DisassociateTrialComponentInput`](crate::operation::disassociate_trial_component::DisassociateTrialComponentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateTrialComponentInputBuilder {
    pub(crate) trial_component_name: ::std::option::Option<::std::string::String>,
    pub(crate) trial_name: ::std::option::Option<::std::string::String>,
}
impl DisassociateTrialComponentInputBuilder {
    /// <p>The name of the component to disassociate from the trial.</p>
    /// This field is required.
    pub fn trial_component_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.trial_component_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the component to disassociate from the trial.</p>
    pub fn set_trial_component_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.trial_component_name = input;
        self
    }
    /// <p>The name of the component to disassociate from the trial.</p>
    pub fn get_trial_component_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.trial_component_name
    }
    /// <p>The name of the trial to disassociate from.</p>
    /// This field is required.
    pub fn trial_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.trial_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the trial to disassociate from.</p>
    pub fn set_trial_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.trial_name = input;
        self
    }
    /// <p>The name of the trial to disassociate from.</p>
    pub fn get_trial_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.trial_name
    }
    /// Consumes the builder and constructs a [`DisassociateTrialComponentInput`](crate::operation::disassociate_trial_component::DisassociateTrialComponentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_trial_component::DisassociateTrialComponentInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::disassociate_trial_component::DisassociateTrialComponentInput {
            trial_component_name: self.trial_component_name,
            trial_name: self.trial_name,
        })
    }
}
