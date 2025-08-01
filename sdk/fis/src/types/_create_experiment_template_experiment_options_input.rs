// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies experiment options for an experiment template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateExperimentTemplateExperimentOptionsInput {
    /// <p>Specifies the account targeting setting for experiment options.</p>
    pub account_targeting: ::std::option::Option<crate::types::AccountTargeting>,
    /// <p>Specifies the empty target resolution mode for experiment options.</p>
    pub empty_target_resolution_mode: ::std::option::Option<crate::types::EmptyTargetResolutionMode>,
}
impl CreateExperimentTemplateExperimentOptionsInput {
    /// <p>Specifies the account targeting setting for experiment options.</p>
    pub fn account_targeting(&self) -> ::std::option::Option<&crate::types::AccountTargeting> {
        self.account_targeting.as_ref()
    }
    /// <p>Specifies the empty target resolution mode for experiment options.</p>
    pub fn empty_target_resolution_mode(&self) -> ::std::option::Option<&crate::types::EmptyTargetResolutionMode> {
        self.empty_target_resolution_mode.as_ref()
    }
}
impl CreateExperimentTemplateExperimentOptionsInput {
    /// Creates a new builder-style object to manufacture [`CreateExperimentTemplateExperimentOptionsInput`](crate::types::CreateExperimentTemplateExperimentOptionsInput).
    pub fn builder() -> crate::types::builders::CreateExperimentTemplateExperimentOptionsInputBuilder {
        crate::types::builders::CreateExperimentTemplateExperimentOptionsInputBuilder::default()
    }
}

/// A builder for [`CreateExperimentTemplateExperimentOptionsInput`](crate::types::CreateExperimentTemplateExperimentOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateExperimentTemplateExperimentOptionsInputBuilder {
    pub(crate) account_targeting: ::std::option::Option<crate::types::AccountTargeting>,
    pub(crate) empty_target_resolution_mode: ::std::option::Option<crate::types::EmptyTargetResolutionMode>,
}
impl CreateExperimentTemplateExperimentOptionsInputBuilder {
    /// <p>Specifies the account targeting setting for experiment options.</p>
    pub fn account_targeting(mut self, input: crate::types::AccountTargeting) -> Self {
        self.account_targeting = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the account targeting setting for experiment options.</p>
    pub fn set_account_targeting(mut self, input: ::std::option::Option<crate::types::AccountTargeting>) -> Self {
        self.account_targeting = input;
        self
    }
    /// <p>Specifies the account targeting setting for experiment options.</p>
    pub fn get_account_targeting(&self) -> &::std::option::Option<crate::types::AccountTargeting> {
        &self.account_targeting
    }
    /// <p>Specifies the empty target resolution mode for experiment options.</p>
    pub fn empty_target_resolution_mode(mut self, input: crate::types::EmptyTargetResolutionMode) -> Self {
        self.empty_target_resolution_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the empty target resolution mode for experiment options.</p>
    pub fn set_empty_target_resolution_mode(mut self, input: ::std::option::Option<crate::types::EmptyTargetResolutionMode>) -> Self {
        self.empty_target_resolution_mode = input;
        self
    }
    /// <p>Specifies the empty target resolution mode for experiment options.</p>
    pub fn get_empty_target_resolution_mode(&self) -> &::std::option::Option<crate::types::EmptyTargetResolutionMode> {
        &self.empty_target_resolution_mode
    }
    /// Consumes the builder and constructs a [`CreateExperimentTemplateExperimentOptionsInput`](crate::types::CreateExperimentTemplateExperimentOptionsInput).
    pub fn build(self) -> crate::types::CreateExperimentTemplateExperimentOptionsInput {
        crate::types::CreateExperimentTemplateExperimentOptionsInput {
            account_targeting: self.account_targeting,
            empty_target_resolution_mode: self.empty_target_resolution_mode,
        }
    }
}
