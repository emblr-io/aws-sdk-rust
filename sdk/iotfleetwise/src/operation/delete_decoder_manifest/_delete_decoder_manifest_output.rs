// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDecoderManifestOutput {
    /// <p>The name of the deleted decoder manifest.</p>
    pub name: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the deleted decoder manifest.</p>
    pub arn: ::std::string::String,
    _request_id: Option<String>,
}
impl DeleteDecoderManifestOutput {
    /// <p>The name of the deleted decoder manifest.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the deleted decoder manifest.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteDecoderManifestOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteDecoderManifestOutput {
    /// Creates a new builder-style object to manufacture [`DeleteDecoderManifestOutput`](crate::operation::delete_decoder_manifest::DeleteDecoderManifestOutput).
    pub fn builder() -> crate::operation::delete_decoder_manifest::builders::DeleteDecoderManifestOutputBuilder {
        crate::operation::delete_decoder_manifest::builders::DeleteDecoderManifestOutputBuilder::default()
    }
}

/// A builder for [`DeleteDecoderManifestOutput`](crate::operation::delete_decoder_manifest::DeleteDecoderManifestOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDecoderManifestOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteDecoderManifestOutputBuilder {
    /// <p>The name of the deleted decoder manifest.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the deleted decoder manifest.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the deleted decoder manifest.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the deleted decoder manifest.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the deleted decoder manifest.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the deleted decoder manifest.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteDecoderManifestOutput`](crate::operation::delete_decoder_manifest::DeleteDecoderManifestOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::operation::delete_decoder_manifest::builders::DeleteDecoderManifestOutputBuilder::name)
    /// - [`arn`](crate::operation::delete_decoder_manifest::builders::DeleteDecoderManifestOutputBuilder::arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_decoder_manifest::DeleteDecoderManifestOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_decoder_manifest::DeleteDecoderManifestOutput {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DeleteDecoderManifestOutput",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building DeleteDecoderManifestOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
