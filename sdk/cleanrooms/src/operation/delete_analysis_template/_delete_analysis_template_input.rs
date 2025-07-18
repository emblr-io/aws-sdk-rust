// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAnalysisTemplateInput {
    /// <p>The identifier for a membership resource.</p>
    pub membership_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the analysis template resource.</p>
    pub analysis_template_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteAnalysisTemplateInput {
    /// <p>The identifier for a membership resource.</p>
    pub fn membership_identifier(&self) -> ::std::option::Option<&str> {
        self.membership_identifier.as_deref()
    }
    /// <p>The identifier for the analysis template resource.</p>
    pub fn analysis_template_identifier(&self) -> ::std::option::Option<&str> {
        self.analysis_template_identifier.as_deref()
    }
}
impl DeleteAnalysisTemplateInput {
    /// Creates a new builder-style object to manufacture [`DeleteAnalysisTemplateInput`](crate::operation::delete_analysis_template::DeleteAnalysisTemplateInput).
    pub fn builder() -> crate::operation::delete_analysis_template::builders::DeleteAnalysisTemplateInputBuilder {
        crate::operation::delete_analysis_template::builders::DeleteAnalysisTemplateInputBuilder::default()
    }
}

/// A builder for [`DeleteAnalysisTemplateInput`](crate::operation::delete_analysis_template::DeleteAnalysisTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAnalysisTemplateInputBuilder {
    pub(crate) membership_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) analysis_template_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteAnalysisTemplateInputBuilder {
    /// <p>The identifier for a membership resource.</p>
    /// This field is required.
    pub fn membership_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for a membership resource.</p>
    pub fn set_membership_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_identifier = input;
        self
    }
    /// <p>The identifier for a membership resource.</p>
    pub fn get_membership_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_identifier
    }
    /// <p>The identifier for the analysis template resource.</p>
    /// This field is required.
    pub fn analysis_template_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.analysis_template_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the analysis template resource.</p>
    pub fn set_analysis_template_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.analysis_template_identifier = input;
        self
    }
    /// <p>The identifier for the analysis template resource.</p>
    pub fn get_analysis_template_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.analysis_template_identifier
    }
    /// Consumes the builder and constructs a [`DeleteAnalysisTemplateInput`](crate::operation::delete_analysis_template::DeleteAnalysisTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_analysis_template::DeleteAnalysisTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_analysis_template::DeleteAnalysisTemplateInput {
            membership_identifier: self.membership_identifier,
            analysis_template_identifier: self.analysis_template_identifier,
        })
    }
}
