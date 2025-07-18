// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutSigningProfileInput {
    /// <p>The name of the signing profile to be created.</p>
    pub profile_name: ::std::option::Option<::std::string::String>,
    /// <p>The AWS Certificate Manager certificate that will be used to sign code with the new signing profile.</p>
    pub signing_material: ::std::option::Option<crate::types::SigningMaterial>,
    /// <p>The default validity period override for any signature generated using this signing profile. If unspecified, the default is 135 months.</p>
    pub signature_validity_period: ::std::option::Option<crate::types::SignatureValidityPeriod>,
    /// <p>The ID of the signing platform to be created.</p>
    pub platform_id: ::std::option::Option<::std::string::String>,
    /// <p>A subfield of <code>platform</code>. This specifies any different configuration options that you want to apply to the chosen platform (such as a different <code>hash-algorithm</code> or <code>signing-algorithm</code>).</p>
    pub overrides: ::std::option::Option<crate::types::SigningPlatformOverrides>,
    /// <p>Map of key-value pairs for signing. These can include any information that you want to use during signing.</p>
    pub signing_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Tags to be associated with the signing profile that is being created.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PutSigningProfileInput {
    /// <p>The name of the signing profile to be created.</p>
    pub fn profile_name(&self) -> ::std::option::Option<&str> {
        self.profile_name.as_deref()
    }
    /// <p>The AWS Certificate Manager certificate that will be used to sign code with the new signing profile.</p>
    pub fn signing_material(&self) -> ::std::option::Option<&crate::types::SigningMaterial> {
        self.signing_material.as_ref()
    }
    /// <p>The default validity period override for any signature generated using this signing profile. If unspecified, the default is 135 months.</p>
    pub fn signature_validity_period(&self) -> ::std::option::Option<&crate::types::SignatureValidityPeriod> {
        self.signature_validity_period.as_ref()
    }
    /// <p>The ID of the signing platform to be created.</p>
    pub fn platform_id(&self) -> ::std::option::Option<&str> {
        self.platform_id.as_deref()
    }
    /// <p>A subfield of <code>platform</code>. This specifies any different configuration options that you want to apply to the chosen platform (such as a different <code>hash-algorithm</code> or <code>signing-algorithm</code>).</p>
    pub fn overrides(&self) -> ::std::option::Option<&crate::types::SigningPlatformOverrides> {
        self.overrides.as_ref()
    }
    /// <p>Map of key-value pairs for signing. These can include any information that you want to use during signing.</p>
    pub fn signing_parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.signing_parameters.as_ref()
    }
    /// <p>Tags to be associated with the signing profile that is being created.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl PutSigningProfileInput {
    /// Creates a new builder-style object to manufacture [`PutSigningProfileInput`](crate::operation::put_signing_profile::PutSigningProfileInput).
    pub fn builder() -> crate::operation::put_signing_profile::builders::PutSigningProfileInputBuilder {
        crate::operation::put_signing_profile::builders::PutSigningProfileInputBuilder::default()
    }
}

/// A builder for [`PutSigningProfileInput`](crate::operation::put_signing_profile::PutSigningProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutSigningProfileInputBuilder {
    pub(crate) profile_name: ::std::option::Option<::std::string::String>,
    pub(crate) signing_material: ::std::option::Option<crate::types::SigningMaterial>,
    pub(crate) signature_validity_period: ::std::option::Option<crate::types::SignatureValidityPeriod>,
    pub(crate) platform_id: ::std::option::Option<::std::string::String>,
    pub(crate) overrides: ::std::option::Option<crate::types::SigningPlatformOverrides>,
    pub(crate) signing_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PutSigningProfileInputBuilder {
    /// <p>The name of the signing profile to be created.</p>
    /// This field is required.
    pub fn profile_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the signing profile to be created.</p>
    pub fn set_profile_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_name = input;
        self
    }
    /// <p>The name of the signing profile to be created.</p>
    pub fn get_profile_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_name
    }
    /// <p>The AWS Certificate Manager certificate that will be used to sign code with the new signing profile.</p>
    pub fn signing_material(mut self, input: crate::types::SigningMaterial) -> Self {
        self.signing_material = ::std::option::Option::Some(input);
        self
    }
    /// <p>The AWS Certificate Manager certificate that will be used to sign code with the new signing profile.</p>
    pub fn set_signing_material(mut self, input: ::std::option::Option<crate::types::SigningMaterial>) -> Self {
        self.signing_material = input;
        self
    }
    /// <p>The AWS Certificate Manager certificate that will be used to sign code with the new signing profile.</p>
    pub fn get_signing_material(&self) -> &::std::option::Option<crate::types::SigningMaterial> {
        &self.signing_material
    }
    /// <p>The default validity period override for any signature generated using this signing profile. If unspecified, the default is 135 months.</p>
    pub fn signature_validity_period(mut self, input: crate::types::SignatureValidityPeriod) -> Self {
        self.signature_validity_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default validity period override for any signature generated using this signing profile. If unspecified, the default is 135 months.</p>
    pub fn set_signature_validity_period(mut self, input: ::std::option::Option<crate::types::SignatureValidityPeriod>) -> Self {
        self.signature_validity_period = input;
        self
    }
    /// <p>The default validity period override for any signature generated using this signing profile. If unspecified, the default is 135 months.</p>
    pub fn get_signature_validity_period(&self) -> &::std::option::Option<crate::types::SignatureValidityPeriod> {
        &self.signature_validity_period
    }
    /// <p>The ID of the signing platform to be created.</p>
    /// This field is required.
    pub fn platform_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the signing platform to be created.</p>
    pub fn set_platform_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform_id = input;
        self
    }
    /// <p>The ID of the signing platform to be created.</p>
    pub fn get_platform_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform_id
    }
    /// <p>A subfield of <code>platform</code>. This specifies any different configuration options that you want to apply to the chosen platform (such as a different <code>hash-algorithm</code> or <code>signing-algorithm</code>).</p>
    pub fn overrides(mut self, input: crate::types::SigningPlatformOverrides) -> Self {
        self.overrides = ::std::option::Option::Some(input);
        self
    }
    /// <p>A subfield of <code>platform</code>. This specifies any different configuration options that you want to apply to the chosen platform (such as a different <code>hash-algorithm</code> or <code>signing-algorithm</code>).</p>
    pub fn set_overrides(mut self, input: ::std::option::Option<crate::types::SigningPlatformOverrides>) -> Self {
        self.overrides = input;
        self
    }
    /// <p>A subfield of <code>platform</code>. This specifies any different configuration options that you want to apply to the chosen platform (such as a different <code>hash-algorithm</code> or <code>signing-algorithm</code>).</p>
    pub fn get_overrides(&self) -> &::std::option::Option<crate::types::SigningPlatformOverrides> {
        &self.overrides
    }
    /// Adds a key-value pair to `signing_parameters`.
    ///
    /// To override the contents of this collection use [`set_signing_parameters`](Self::set_signing_parameters).
    ///
    /// <p>Map of key-value pairs for signing. These can include any information that you want to use during signing.</p>
    pub fn signing_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.signing_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.signing_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Map of key-value pairs for signing. These can include any information that you want to use during signing.</p>
    pub fn set_signing_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.signing_parameters = input;
        self
    }
    /// <p>Map of key-value pairs for signing. These can include any information that you want to use during signing.</p>
    pub fn get_signing_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.signing_parameters
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags to be associated with the signing profile that is being created.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags to be associated with the signing profile that is being created.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags to be associated with the signing profile that is being created.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`PutSigningProfileInput`](crate::operation::put_signing_profile::PutSigningProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_signing_profile::PutSigningProfileInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_signing_profile::PutSigningProfileInput {
            profile_name: self.profile_name,
            signing_material: self.signing_material,
            signature_validity_period: self.signature_validity_period,
            platform_id: self.platform_id,
            overrides: self.overrides,
            signing_parameters: self.signing_parameters,
            tags: self.tags,
        })
    }
}
