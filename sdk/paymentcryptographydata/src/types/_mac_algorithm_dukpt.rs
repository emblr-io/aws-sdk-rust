// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters required for DUKPT MAC generation and verification.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MacAlgorithmDukpt {
    /// <p>The unique identifier known as Key Serial Number (KSN) that comes from an encrypting device using DUKPT encryption method. The KSN is derived from the encrypting device unique identifier and an internal transaction counter.</p>
    pub key_serial_number: ::std::string::String,
    /// <p>The type of use of DUKPT, which can be MAC generation, MAC verification, or both.</p>
    pub dukpt_key_variant: crate::types::DukptKeyVariant,
    /// <p>The key type derived using DUKPT from a Base Derivation Key (BDK) and Key Serial Number (KSN). This must be less than or equal to the strength of the BDK. For example, you can't use <code>AES_128</code> as a derivation type for a BDK of <code>AES_128</code> or <code>TDES_2KEY</code>.</p>
    pub dukpt_derivation_type: ::std::option::Option<crate::types::DukptDerivationType>,
}
impl MacAlgorithmDukpt {
    /// <p>The unique identifier known as Key Serial Number (KSN) that comes from an encrypting device using DUKPT encryption method. The KSN is derived from the encrypting device unique identifier and an internal transaction counter.</p>
    pub fn key_serial_number(&self) -> &str {
        use std::ops::Deref;
        self.key_serial_number.deref()
    }
    /// <p>The type of use of DUKPT, which can be MAC generation, MAC verification, or both.</p>
    pub fn dukpt_key_variant(&self) -> &crate::types::DukptKeyVariant {
        &self.dukpt_key_variant
    }
    /// <p>The key type derived using DUKPT from a Base Derivation Key (BDK) and Key Serial Number (KSN). This must be less than or equal to the strength of the BDK. For example, you can't use <code>AES_128</code> as a derivation type for a BDK of <code>AES_128</code> or <code>TDES_2KEY</code>.</p>
    pub fn dukpt_derivation_type(&self) -> ::std::option::Option<&crate::types::DukptDerivationType> {
        self.dukpt_derivation_type.as_ref()
    }
}
impl MacAlgorithmDukpt {
    /// Creates a new builder-style object to manufacture [`MacAlgorithmDukpt`](crate::types::MacAlgorithmDukpt).
    pub fn builder() -> crate::types::builders::MacAlgorithmDukptBuilder {
        crate::types::builders::MacAlgorithmDukptBuilder::default()
    }
}

/// A builder for [`MacAlgorithmDukpt`](crate::types::MacAlgorithmDukpt).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MacAlgorithmDukptBuilder {
    pub(crate) key_serial_number: ::std::option::Option<::std::string::String>,
    pub(crate) dukpt_key_variant: ::std::option::Option<crate::types::DukptKeyVariant>,
    pub(crate) dukpt_derivation_type: ::std::option::Option<crate::types::DukptDerivationType>,
}
impl MacAlgorithmDukptBuilder {
    /// <p>The unique identifier known as Key Serial Number (KSN) that comes from an encrypting device using DUKPT encryption method. The KSN is derived from the encrypting device unique identifier and an internal transaction counter.</p>
    /// This field is required.
    pub fn key_serial_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_serial_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier known as Key Serial Number (KSN) that comes from an encrypting device using DUKPT encryption method. The KSN is derived from the encrypting device unique identifier and an internal transaction counter.</p>
    pub fn set_key_serial_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_serial_number = input;
        self
    }
    /// <p>The unique identifier known as Key Serial Number (KSN) that comes from an encrypting device using DUKPT encryption method. The KSN is derived from the encrypting device unique identifier and an internal transaction counter.</p>
    pub fn get_key_serial_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_serial_number
    }
    /// <p>The type of use of DUKPT, which can be MAC generation, MAC verification, or both.</p>
    /// This field is required.
    pub fn dukpt_key_variant(mut self, input: crate::types::DukptKeyVariant) -> Self {
        self.dukpt_key_variant = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of use of DUKPT, which can be MAC generation, MAC verification, or both.</p>
    pub fn set_dukpt_key_variant(mut self, input: ::std::option::Option<crate::types::DukptKeyVariant>) -> Self {
        self.dukpt_key_variant = input;
        self
    }
    /// <p>The type of use of DUKPT, which can be MAC generation, MAC verification, or both.</p>
    pub fn get_dukpt_key_variant(&self) -> &::std::option::Option<crate::types::DukptKeyVariant> {
        &self.dukpt_key_variant
    }
    /// <p>The key type derived using DUKPT from a Base Derivation Key (BDK) and Key Serial Number (KSN). This must be less than or equal to the strength of the BDK. For example, you can't use <code>AES_128</code> as a derivation type for a BDK of <code>AES_128</code> or <code>TDES_2KEY</code>.</p>
    pub fn dukpt_derivation_type(mut self, input: crate::types::DukptDerivationType) -> Self {
        self.dukpt_derivation_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The key type derived using DUKPT from a Base Derivation Key (BDK) and Key Serial Number (KSN). This must be less than or equal to the strength of the BDK. For example, you can't use <code>AES_128</code> as a derivation type for a BDK of <code>AES_128</code> or <code>TDES_2KEY</code>.</p>
    pub fn set_dukpt_derivation_type(mut self, input: ::std::option::Option<crate::types::DukptDerivationType>) -> Self {
        self.dukpt_derivation_type = input;
        self
    }
    /// <p>The key type derived using DUKPT from a Base Derivation Key (BDK) and Key Serial Number (KSN). This must be less than or equal to the strength of the BDK. For example, you can't use <code>AES_128</code> as a derivation type for a BDK of <code>AES_128</code> or <code>TDES_2KEY</code>.</p>
    pub fn get_dukpt_derivation_type(&self) -> &::std::option::Option<crate::types::DukptDerivationType> {
        &self.dukpt_derivation_type
    }
    /// Consumes the builder and constructs a [`MacAlgorithmDukpt`](crate::types::MacAlgorithmDukpt).
    /// This method will fail if any of the following fields are not set:
    /// - [`key_serial_number`](crate::types::builders::MacAlgorithmDukptBuilder::key_serial_number)
    /// - [`dukpt_key_variant`](crate::types::builders::MacAlgorithmDukptBuilder::dukpt_key_variant)
    pub fn build(self) -> ::std::result::Result<crate::types::MacAlgorithmDukpt, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MacAlgorithmDukpt {
            key_serial_number: self.key_serial_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key_serial_number",
                    "key_serial_number was not specified but it is required when building MacAlgorithmDukpt",
                )
            })?,
            dukpt_key_variant: self.dukpt_key_variant.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dukpt_key_variant",
                    "dukpt_key_variant was not specified but it is required when building MacAlgorithmDukpt",
                )
            })?,
            dukpt_derivation_type: self.dukpt_derivation_type,
        })
    }
}
