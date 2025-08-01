// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAnalyzerInput {
    /// <p>The name of the analyzer to modify.</p>
    pub analyzer_name: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about the configuration of an analyzer for an Amazon Web Services organization or account.</p>
    pub configuration: ::std::option::Option<crate::types::AnalyzerConfiguration>,
}
impl UpdateAnalyzerInput {
    /// <p>The name of the analyzer to modify.</p>
    pub fn analyzer_name(&self) -> ::std::option::Option<&str> {
        self.analyzer_name.as_deref()
    }
    /// <p>Contains information about the configuration of an analyzer for an Amazon Web Services organization or account.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::AnalyzerConfiguration> {
        self.configuration.as_ref()
    }
}
impl UpdateAnalyzerInput {
    /// Creates a new builder-style object to manufacture [`UpdateAnalyzerInput`](crate::operation::update_analyzer::UpdateAnalyzerInput).
    pub fn builder() -> crate::operation::update_analyzer::builders::UpdateAnalyzerInputBuilder {
        crate::operation::update_analyzer::builders::UpdateAnalyzerInputBuilder::default()
    }
}

/// A builder for [`UpdateAnalyzerInput`](crate::operation::update_analyzer::UpdateAnalyzerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAnalyzerInputBuilder {
    pub(crate) analyzer_name: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<crate::types::AnalyzerConfiguration>,
}
impl UpdateAnalyzerInputBuilder {
    /// <p>The name of the analyzer to modify.</p>
    /// This field is required.
    pub fn analyzer_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.analyzer_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the analyzer to modify.</p>
    pub fn set_analyzer_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.analyzer_name = input;
        self
    }
    /// <p>The name of the analyzer to modify.</p>
    pub fn get_analyzer_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.analyzer_name
    }
    /// <p>Contains information about the configuration of an analyzer for an Amazon Web Services organization or account.</p>
    pub fn configuration(mut self, input: crate::types::AnalyzerConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the configuration of an analyzer for an Amazon Web Services organization or account.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::AnalyzerConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>Contains information about the configuration of an analyzer for an Amazon Web Services organization or account.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::AnalyzerConfiguration> {
        &self.configuration
    }
    /// Consumes the builder and constructs a [`UpdateAnalyzerInput`](crate::operation::update_analyzer::UpdateAnalyzerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_analyzer::UpdateAnalyzerInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_analyzer::UpdateAnalyzerInput {
            analyzer_name: self.analyzer_name,
            configuration: self.configuration,
        })
    }
}
