// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The audio artifact configuration object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AudioArtifactsConfiguration {
    /// <p>The MUX type of the audio artifact configuration object.</p>
    pub mux_type: crate::types::AudioMuxType,
}
impl AudioArtifactsConfiguration {
    /// <p>The MUX type of the audio artifact configuration object.</p>
    pub fn mux_type(&self) -> &crate::types::AudioMuxType {
        &self.mux_type
    }
}
impl AudioArtifactsConfiguration {
    /// Creates a new builder-style object to manufacture [`AudioArtifactsConfiguration`](crate::types::AudioArtifactsConfiguration).
    pub fn builder() -> crate::types::builders::AudioArtifactsConfigurationBuilder {
        crate::types::builders::AudioArtifactsConfigurationBuilder::default()
    }
}

/// A builder for [`AudioArtifactsConfiguration`](crate::types::AudioArtifactsConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AudioArtifactsConfigurationBuilder {
    pub(crate) mux_type: ::std::option::Option<crate::types::AudioMuxType>,
}
impl AudioArtifactsConfigurationBuilder {
    /// <p>The MUX type of the audio artifact configuration object.</p>
    /// This field is required.
    pub fn mux_type(mut self, input: crate::types::AudioMuxType) -> Self {
        self.mux_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The MUX type of the audio artifact configuration object.</p>
    pub fn set_mux_type(mut self, input: ::std::option::Option<crate::types::AudioMuxType>) -> Self {
        self.mux_type = input;
        self
    }
    /// <p>The MUX type of the audio artifact configuration object.</p>
    pub fn get_mux_type(&self) -> &::std::option::Option<crate::types::AudioMuxType> {
        &self.mux_type
    }
    /// Consumes the builder and constructs a [`AudioArtifactsConfiguration`](crate::types::AudioArtifactsConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`mux_type`](crate::types::builders::AudioArtifactsConfigurationBuilder::mux_type)
    pub fn build(self) -> ::std::result::Result<crate::types::AudioArtifactsConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AudioArtifactsConfiguration {
            mux_type: self.mux_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "mux_type",
                    "mux_type was not specified but it is required when building AudioArtifactsConfiguration",
                )
            })?,
        })
    }
}
