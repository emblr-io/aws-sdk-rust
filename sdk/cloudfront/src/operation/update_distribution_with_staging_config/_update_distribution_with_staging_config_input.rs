// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDistributionWithStagingConfigInput {
    /// <p>The identifier of the primary distribution to which you are copying a staging distribution's configuration.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the staging distribution whose configuration you are copying to the primary distribution.</p>
    pub staging_distribution_id: ::std::option::Option<::std::string::String>,
    /// <p>The current versions (<code>ETag</code> values) of both primary and staging distributions. Provide these in the following format:</p>
    /// <p><code>&lt;primary ETag&gt;, &lt;staging ETag&gt;</code></p>
    pub if_match: ::std::option::Option<::std::string::String>,
}
impl UpdateDistributionWithStagingConfigInput {
    /// <p>The identifier of the primary distribution to which you are copying a staging distribution's configuration.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The identifier of the staging distribution whose configuration you are copying to the primary distribution.</p>
    pub fn staging_distribution_id(&self) -> ::std::option::Option<&str> {
        self.staging_distribution_id.as_deref()
    }
    /// <p>The current versions (<code>ETag</code> values) of both primary and staging distributions. Provide these in the following format:</p>
    /// <p><code>&lt;primary ETag&gt;, &lt;staging ETag&gt;</code></p>
    pub fn if_match(&self) -> ::std::option::Option<&str> {
        self.if_match.as_deref()
    }
}
impl UpdateDistributionWithStagingConfigInput {
    /// Creates a new builder-style object to manufacture [`UpdateDistributionWithStagingConfigInput`](crate::operation::update_distribution_with_staging_config::UpdateDistributionWithStagingConfigInput).
    pub fn builder() -> crate::operation::update_distribution_with_staging_config::builders::UpdateDistributionWithStagingConfigInputBuilder {
        crate::operation::update_distribution_with_staging_config::builders::UpdateDistributionWithStagingConfigInputBuilder::default()
    }
}

/// A builder for [`UpdateDistributionWithStagingConfigInput`](crate::operation::update_distribution_with_staging_config::UpdateDistributionWithStagingConfigInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDistributionWithStagingConfigInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) staging_distribution_id: ::std::option::Option<::std::string::String>,
    pub(crate) if_match: ::std::option::Option<::std::string::String>,
}
impl UpdateDistributionWithStagingConfigInputBuilder {
    /// <p>The identifier of the primary distribution to which you are copying a staging distribution's configuration.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the primary distribution to which you are copying a staging distribution's configuration.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the primary distribution to which you are copying a staging distribution's configuration.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The identifier of the staging distribution whose configuration you are copying to the primary distribution.</p>
    pub fn staging_distribution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.staging_distribution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the staging distribution whose configuration you are copying to the primary distribution.</p>
    pub fn set_staging_distribution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.staging_distribution_id = input;
        self
    }
    /// <p>The identifier of the staging distribution whose configuration you are copying to the primary distribution.</p>
    pub fn get_staging_distribution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.staging_distribution_id
    }
    /// <p>The current versions (<code>ETag</code> values) of both primary and staging distributions. Provide these in the following format:</p>
    /// <p><code>&lt;primary ETag&gt;, &lt;staging ETag&gt;</code></p>
    pub fn if_match(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.if_match = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current versions (<code>ETag</code> values) of both primary and staging distributions. Provide these in the following format:</p>
    /// <p><code>&lt;primary ETag&gt;, &lt;staging ETag&gt;</code></p>
    pub fn set_if_match(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.if_match = input;
        self
    }
    /// <p>The current versions (<code>ETag</code> values) of both primary and staging distributions. Provide these in the following format:</p>
    /// <p><code>&lt;primary ETag&gt;, &lt;staging ETag&gt;</code></p>
    pub fn get_if_match(&self) -> &::std::option::Option<::std::string::String> {
        &self.if_match
    }
    /// Consumes the builder and constructs a [`UpdateDistributionWithStagingConfigInput`](crate::operation::update_distribution_with_staging_config::UpdateDistributionWithStagingConfigInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_distribution_with_staging_config::UpdateDistributionWithStagingConfigInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_distribution_with_staging_config::UpdateDistributionWithStagingConfigInput {
                id: self.id,
                staging_distribution_id: self.staging_distribution_id,
                if_match: self.if_match,
            },
        )
    }
}
