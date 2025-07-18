// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>ListVolumeInitiatorsInput</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListVolumeInitiatorsInput {
    /// <p>The Amazon Resource Name (ARN) of the volume. Use the <code>ListVolumes</code> operation to return a list of gateway volumes for the gateway.</p>
    pub volume_arn: ::std::option::Option<::std::string::String>,
}
impl ListVolumeInitiatorsInput {
    /// <p>The Amazon Resource Name (ARN) of the volume. Use the <code>ListVolumes</code> operation to return a list of gateway volumes for the gateway.</p>
    pub fn volume_arn(&self) -> ::std::option::Option<&str> {
        self.volume_arn.as_deref()
    }
}
impl ListVolumeInitiatorsInput {
    /// Creates a new builder-style object to manufacture [`ListVolumeInitiatorsInput`](crate::operation::list_volume_initiators::ListVolumeInitiatorsInput).
    pub fn builder() -> crate::operation::list_volume_initiators::builders::ListVolumeInitiatorsInputBuilder {
        crate::operation::list_volume_initiators::builders::ListVolumeInitiatorsInputBuilder::default()
    }
}

/// A builder for [`ListVolumeInitiatorsInput`](crate::operation::list_volume_initiators::ListVolumeInitiatorsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListVolumeInitiatorsInputBuilder {
    pub(crate) volume_arn: ::std::option::Option<::std::string::String>,
}
impl ListVolumeInitiatorsInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the volume. Use the <code>ListVolumes</code> operation to return a list of gateway volumes for the gateway.</p>
    /// This field is required.
    pub fn volume_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the volume. Use the <code>ListVolumes</code> operation to return a list of gateway volumes for the gateway.</p>
    pub fn set_volume_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the volume. Use the <code>ListVolumes</code> operation to return a list of gateway volumes for the gateway.</p>
    pub fn get_volume_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_arn
    }
    /// Consumes the builder and constructs a [`ListVolumeInitiatorsInput`](crate::operation::list_volume_initiators::ListVolumeInitiatorsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_volume_initiators::ListVolumeInitiatorsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_volume_initiators::ListVolumeInitiatorsInput { volume_arn: self.volume_arn })
    }
}
