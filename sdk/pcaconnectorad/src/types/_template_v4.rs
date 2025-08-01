// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>v4 template schema that can use either Legacy Cryptographic Providers or Key Storage Providers.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TemplateV4 {
    /// <p>Certificate validity describes the validity and renewal periods of a certificate.</p>
    pub certificate_validity: ::std::option::Option<crate::types::CertificateValidity>,
    /// <p>List of templates in Active Directory that are superseded by this template.</p>
    pub superseded_templates: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, key usage, and cryptographic providers for the private key of a certificate for v4 templates. V4 templates allow you to use either Key Storage Providers or Legacy Cryptographic Service Providers. You specify the cryptography provider category in private key flags.</p>
    pub private_key_attributes: ::std::option::Option<crate::types::PrivateKeyAttributesV4>,
    /// <p>Private key flags for v4 templates specify the client compatibility, if the private key can be exported, if user input is required when using a private key, if an alternate signature algorithm should be used, and if certificates are renewed using the same private key.</p>
    pub private_key_flags: ::std::option::Option<crate::types::PrivateKeyFlagsV4>,
    /// <p>Enrollment flags describe the enrollment settings for certificates using the existing private key and deleting expired or revoked certificates.</p>
    pub enrollment_flags: ::std::option::Option<crate::types::EnrollmentFlagsV4>,
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    pub subject_name_flags: ::std::option::Option<crate::types::SubjectNameFlagsV4>,
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    pub general_flags: ::std::option::Option<crate::types::GeneralFlagsV4>,
    /// <p>Specifies the hash algorithm used to hash the private key. Hash algorithm can only be specified when using Key Storage Providers.</p>
    pub hash_algorithm: ::std::option::Option<crate::types::HashAlgorithm>,
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    pub extensions: ::std::option::Option<crate::types::ExtensionsV4>,
}
impl TemplateV4 {
    /// <p>Certificate validity describes the validity and renewal periods of a certificate.</p>
    pub fn certificate_validity(&self) -> ::std::option::Option<&crate::types::CertificateValidity> {
        self.certificate_validity.as_ref()
    }
    /// <p>List of templates in Active Directory that are superseded by this template.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.superseded_templates.is_none()`.
    pub fn superseded_templates(&self) -> &[::std::string::String] {
        self.superseded_templates.as_deref().unwrap_or_default()
    }
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, key usage, and cryptographic providers for the private key of a certificate for v4 templates. V4 templates allow you to use either Key Storage Providers or Legacy Cryptographic Service Providers. You specify the cryptography provider category in private key flags.</p>
    pub fn private_key_attributes(&self) -> ::std::option::Option<&crate::types::PrivateKeyAttributesV4> {
        self.private_key_attributes.as_ref()
    }
    /// <p>Private key flags for v4 templates specify the client compatibility, if the private key can be exported, if user input is required when using a private key, if an alternate signature algorithm should be used, and if certificates are renewed using the same private key.</p>
    pub fn private_key_flags(&self) -> ::std::option::Option<&crate::types::PrivateKeyFlagsV4> {
        self.private_key_flags.as_ref()
    }
    /// <p>Enrollment flags describe the enrollment settings for certificates using the existing private key and deleting expired or revoked certificates.</p>
    pub fn enrollment_flags(&self) -> ::std::option::Option<&crate::types::EnrollmentFlagsV4> {
        self.enrollment_flags.as_ref()
    }
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    pub fn subject_name_flags(&self) -> ::std::option::Option<&crate::types::SubjectNameFlagsV4> {
        self.subject_name_flags.as_ref()
    }
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    pub fn general_flags(&self) -> ::std::option::Option<&crate::types::GeneralFlagsV4> {
        self.general_flags.as_ref()
    }
    /// <p>Specifies the hash algorithm used to hash the private key. Hash algorithm can only be specified when using Key Storage Providers.</p>
    pub fn hash_algorithm(&self) -> ::std::option::Option<&crate::types::HashAlgorithm> {
        self.hash_algorithm.as_ref()
    }
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    pub fn extensions(&self) -> ::std::option::Option<&crate::types::ExtensionsV4> {
        self.extensions.as_ref()
    }
}
impl TemplateV4 {
    /// Creates a new builder-style object to manufacture [`TemplateV4`](crate::types::TemplateV4).
    pub fn builder() -> crate::types::builders::TemplateV4Builder {
        crate::types::builders::TemplateV4Builder::default()
    }
}

/// A builder for [`TemplateV4`](crate::types::TemplateV4).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TemplateV4Builder {
    pub(crate) certificate_validity: ::std::option::Option<crate::types::CertificateValidity>,
    pub(crate) superseded_templates: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) private_key_attributes: ::std::option::Option<crate::types::PrivateKeyAttributesV4>,
    pub(crate) private_key_flags: ::std::option::Option<crate::types::PrivateKeyFlagsV4>,
    pub(crate) enrollment_flags: ::std::option::Option<crate::types::EnrollmentFlagsV4>,
    pub(crate) subject_name_flags: ::std::option::Option<crate::types::SubjectNameFlagsV4>,
    pub(crate) general_flags: ::std::option::Option<crate::types::GeneralFlagsV4>,
    pub(crate) hash_algorithm: ::std::option::Option<crate::types::HashAlgorithm>,
    pub(crate) extensions: ::std::option::Option<crate::types::ExtensionsV4>,
}
impl TemplateV4Builder {
    /// <p>Certificate validity describes the validity and renewal periods of a certificate.</p>
    /// This field is required.
    pub fn certificate_validity(mut self, input: crate::types::CertificateValidity) -> Self {
        self.certificate_validity = ::std::option::Option::Some(input);
        self
    }
    /// <p>Certificate validity describes the validity and renewal periods of a certificate.</p>
    pub fn set_certificate_validity(mut self, input: ::std::option::Option<crate::types::CertificateValidity>) -> Self {
        self.certificate_validity = input;
        self
    }
    /// <p>Certificate validity describes the validity and renewal periods of a certificate.</p>
    pub fn get_certificate_validity(&self) -> &::std::option::Option<crate::types::CertificateValidity> {
        &self.certificate_validity
    }
    /// Appends an item to `superseded_templates`.
    ///
    /// To override the contents of this collection use [`set_superseded_templates`](Self::set_superseded_templates).
    ///
    /// <p>List of templates in Active Directory that are superseded by this template.</p>
    pub fn superseded_templates(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.superseded_templates.unwrap_or_default();
        v.push(input.into());
        self.superseded_templates = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of templates in Active Directory that are superseded by this template.</p>
    pub fn set_superseded_templates(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.superseded_templates = input;
        self
    }
    /// <p>List of templates in Active Directory that are superseded by this template.</p>
    pub fn get_superseded_templates(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.superseded_templates
    }
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, key usage, and cryptographic providers for the private key of a certificate for v4 templates. V4 templates allow you to use either Key Storage Providers or Legacy Cryptographic Service Providers. You specify the cryptography provider category in private key flags.</p>
    /// This field is required.
    pub fn private_key_attributes(mut self, input: crate::types::PrivateKeyAttributesV4) -> Self {
        self.private_key_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, key usage, and cryptographic providers for the private key of a certificate for v4 templates. V4 templates allow you to use either Key Storage Providers or Legacy Cryptographic Service Providers. You specify the cryptography provider category in private key flags.</p>
    pub fn set_private_key_attributes(mut self, input: ::std::option::Option<crate::types::PrivateKeyAttributesV4>) -> Self {
        self.private_key_attributes = input;
        self
    }
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, key usage, and cryptographic providers for the private key of a certificate for v4 templates. V4 templates allow you to use either Key Storage Providers or Legacy Cryptographic Service Providers. You specify the cryptography provider category in private key flags.</p>
    pub fn get_private_key_attributes(&self) -> &::std::option::Option<crate::types::PrivateKeyAttributesV4> {
        &self.private_key_attributes
    }
    /// <p>Private key flags for v4 templates specify the client compatibility, if the private key can be exported, if user input is required when using a private key, if an alternate signature algorithm should be used, and if certificates are renewed using the same private key.</p>
    /// This field is required.
    pub fn private_key_flags(mut self, input: crate::types::PrivateKeyFlagsV4) -> Self {
        self.private_key_flags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Private key flags for v4 templates specify the client compatibility, if the private key can be exported, if user input is required when using a private key, if an alternate signature algorithm should be used, and if certificates are renewed using the same private key.</p>
    pub fn set_private_key_flags(mut self, input: ::std::option::Option<crate::types::PrivateKeyFlagsV4>) -> Self {
        self.private_key_flags = input;
        self
    }
    /// <p>Private key flags for v4 templates specify the client compatibility, if the private key can be exported, if user input is required when using a private key, if an alternate signature algorithm should be used, and if certificates are renewed using the same private key.</p>
    pub fn get_private_key_flags(&self) -> &::std::option::Option<crate::types::PrivateKeyFlagsV4> {
        &self.private_key_flags
    }
    /// <p>Enrollment flags describe the enrollment settings for certificates using the existing private key and deleting expired or revoked certificates.</p>
    /// This field is required.
    pub fn enrollment_flags(mut self, input: crate::types::EnrollmentFlagsV4) -> Self {
        self.enrollment_flags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enrollment flags describe the enrollment settings for certificates using the existing private key and deleting expired or revoked certificates.</p>
    pub fn set_enrollment_flags(mut self, input: ::std::option::Option<crate::types::EnrollmentFlagsV4>) -> Self {
        self.enrollment_flags = input;
        self
    }
    /// <p>Enrollment flags describe the enrollment settings for certificates using the existing private key and deleting expired or revoked certificates.</p>
    pub fn get_enrollment_flags(&self) -> &::std::option::Option<crate::types::EnrollmentFlagsV4> {
        &self.enrollment_flags
    }
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    /// This field is required.
    pub fn subject_name_flags(mut self, input: crate::types::SubjectNameFlagsV4) -> Self {
        self.subject_name_flags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    pub fn set_subject_name_flags(mut self, input: ::std::option::Option<crate::types::SubjectNameFlagsV4>) -> Self {
        self.subject_name_flags = input;
        self
    }
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    pub fn get_subject_name_flags(&self) -> &::std::option::Option<crate::types::SubjectNameFlagsV4> {
        &self.subject_name_flags
    }
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    /// This field is required.
    pub fn general_flags(mut self, input: crate::types::GeneralFlagsV4) -> Self {
        self.general_flags = ::std::option::Option::Some(input);
        self
    }
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    pub fn set_general_flags(mut self, input: ::std::option::Option<crate::types::GeneralFlagsV4>) -> Self {
        self.general_flags = input;
        self
    }
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    pub fn get_general_flags(&self) -> &::std::option::Option<crate::types::GeneralFlagsV4> {
        &self.general_flags
    }
    /// <p>Specifies the hash algorithm used to hash the private key. Hash algorithm can only be specified when using Key Storage Providers.</p>
    pub fn hash_algorithm(mut self, input: crate::types::HashAlgorithm) -> Self {
        self.hash_algorithm = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the hash algorithm used to hash the private key. Hash algorithm can only be specified when using Key Storage Providers.</p>
    pub fn set_hash_algorithm(mut self, input: ::std::option::Option<crate::types::HashAlgorithm>) -> Self {
        self.hash_algorithm = input;
        self
    }
    /// <p>Specifies the hash algorithm used to hash the private key. Hash algorithm can only be specified when using Key Storage Providers.</p>
    pub fn get_hash_algorithm(&self) -> &::std::option::Option<crate::types::HashAlgorithm> {
        &self.hash_algorithm
    }
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    /// This field is required.
    pub fn extensions(mut self, input: crate::types::ExtensionsV4) -> Self {
        self.extensions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    pub fn set_extensions(mut self, input: ::std::option::Option<crate::types::ExtensionsV4>) -> Self {
        self.extensions = input;
        self
    }
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    pub fn get_extensions(&self) -> &::std::option::Option<crate::types::ExtensionsV4> {
        &self.extensions
    }
    /// Consumes the builder and constructs a [`TemplateV4`](crate::types::TemplateV4).
    pub fn build(self) -> crate::types::TemplateV4 {
        crate::types::TemplateV4 {
            certificate_validity: self.certificate_validity,
            superseded_templates: self.superseded_templates,
            private_key_attributes: self.private_key_attributes,
            private_key_flags: self.private_key_flags,
            enrollment_flags: self.enrollment_flags,
            subject_name_flags: self.subject_name_flags,
            general_flags: self.general_flags,
            hash_algorithm: self.hash_algorithm,
            extensions: self.extensions,
        }
    }
}
