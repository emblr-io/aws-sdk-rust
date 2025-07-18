// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the dashboard you want to embed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisteredUserDashboardEmbeddingConfiguration {
    /// <p>The dashboard ID for the dashboard that you want the user to see first. This ID is included in the output URL. When the URL in response is accessed, Amazon QuickSight renders this dashboard if the user has permissions to view it.</p>
    /// <p>If the user does not have permission to view this dashboard, they see a permissions error message.</p>
    pub initial_dashboard_id: ::std::string::String,
    /// <p>The feature configurations of an embbedded Amazon QuickSight dashboard.</p>
    pub feature_configurations: ::std::option::Option<crate::types::RegisteredUserDashboardFeatureConfigurations>,
}
impl RegisteredUserDashboardEmbeddingConfiguration {
    /// <p>The dashboard ID for the dashboard that you want the user to see first. This ID is included in the output URL. When the URL in response is accessed, Amazon QuickSight renders this dashboard if the user has permissions to view it.</p>
    /// <p>If the user does not have permission to view this dashboard, they see a permissions error message.</p>
    pub fn initial_dashboard_id(&self) -> &str {
        use std::ops::Deref;
        self.initial_dashboard_id.deref()
    }
    /// <p>The feature configurations of an embbedded Amazon QuickSight dashboard.</p>
    pub fn feature_configurations(&self) -> ::std::option::Option<&crate::types::RegisteredUserDashboardFeatureConfigurations> {
        self.feature_configurations.as_ref()
    }
}
impl RegisteredUserDashboardEmbeddingConfiguration {
    /// Creates a new builder-style object to manufacture [`RegisteredUserDashboardEmbeddingConfiguration`](crate::types::RegisteredUserDashboardEmbeddingConfiguration).
    pub fn builder() -> crate::types::builders::RegisteredUserDashboardEmbeddingConfigurationBuilder {
        crate::types::builders::RegisteredUserDashboardEmbeddingConfigurationBuilder::default()
    }
}

/// A builder for [`RegisteredUserDashboardEmbeddingConfiguration`](crate::types::RegisteredUserDashboardEmbeddingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisteredUserDashboardEmbeddingConfigurationBuilder {
    pub(crate) initial_dashboard_id: ::std::option::Option<::std::string::String>,
    pub(crate) feature_configurations: ::std::option::Option<crate::types::RegisteredUserDashboardFeatureConfigurations>,
}
impl RegisteredUserDashboardEmbeddingConfigurationBuilder {
    /// <p>The dashboard ID for the dashboard that you want the user to see first. This ID is included in the output URL. When the URL in response is accessed, Amazon QuickSight renders this dashboard if the user has permissions to view it.</p>
    /// <p>If the user does not have permission to view this dashboard, they see a permissions error message.</p>
    /// This field is required.
    pub fn initial_dashboard_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.initial_dashboard_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The dashboard ID for the dashboard that you want the user to see first. This ID is included in the output URL. When the URL in response is accessed, Amazon QuickSight renders this dashboard if the user has permissions to view it.</p>
    /// <p>If the user does not have permission to view this dashboard, they see a permissions error message.</p>
    pub fn set_initial_dashboard_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.initial_dashboard_id = input;
        self
    }
    /// <p>The dashboard ID for the dashboard that you want the user to see first. This ID is included in the output URL. When the URL in response is accessed, Amazon QuickSight renders this dashboard if the user has permissions to view it.</p>
    /// <p>If the user does not have permission to view this dashboard, they see a permissions error message.</p>
    pub fn get_initial_dashboard_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.initial_dashboard_id
    }
    /// <p>The feature configurations of an embbedded Amazon QuickSight dashboard.</p>
    pub fn feature_configurations(mut self, input: crate::types::RegisteredUserDashboardFeatureConfigurations) -> Self {
        self.feature_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The feature configurations of an embbedded Amazon QuickSight dashboard.</p>
    pub fn set_feature_configurations(mut self, input: ::std::option::Option<crate::types::RegisteredUserDashboardFeatureConfigurations>) -> Self {
        self.feature_configurations = input;
        self
    }
    /// <p>The feature configurations of an embbedded Amazon QuickSight dashboard.</p>
    pub fn get_feature_configurations(&self) -> &::std::option::Option<crate::types::RegisteredUserDashboardFeatureConfigurations> {
        &self.feature_configurations
    }
    /// Consumes the builder and constructs a [`RegisteredUserDashboardEmbeddingConfiguration`](crate::types::RegisteredUserDashboardEmbeddingConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`initial_dashboard_id`](crate::types::builders::RegisteredUserDashboardEmbeddingConfigurationBuilder::initial_dashboard_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::RegisteredUserDashboardEmbeddingConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RegisteredUserDashboardEmbeddingConfiguration {
            initial_dashboard_id: self.initial_dashboard_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "initial_dashboard_id",
                    "initial_dashboard_id was not specified but it is required when building RegisteredUserDashboardEmbeddingConfiguration",
                )
            })?,
            feature_configurations: self.feature_configurations,
        })
    }
}
