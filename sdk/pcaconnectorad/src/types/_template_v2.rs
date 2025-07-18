// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>v2 template schema that uses Legacy Cryptographic Providers.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TemplateV2 {
    /// <p>Certificate validity describes the validity and renewal periods of a certificate.</p>
    pub certificate_validity: ::std::option::Option<crate::types::CertificateValidity>,
    /// <p>List of templates in Active Directory that are superseded by this template.</p>
    pub superseded_templates: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, and cryptographic providers for the private key of a certificate for v2 templates. V2 templates allow you to use Legacy Cryptographic Service Providers.</p>
    pub private_key_attributes: ::std::option::Option<crate::types::PrivateKeyAttributesV2>,
    /// <p>Private key flags for v2 templates specify the client compatibility, if the private key can be exported, and if user input is required when using a private key.</p>
    pub private_key_flags: ::std::option::Option<crate::types::PrivateKeyFlagsV2>,
    /// <p>Enrollment flags describe the enrollment settings for certificates such as using the existing private key and deleting expired or revoked certificates.</p>
    pub enrollment_flags: ::std::option::Option<crate::types::EnrollmentFlagsV2>,
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    pub subject_name_flags: ::std::option::Option<crate::types::SubjectNameFlagsV2>,
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    pub general_flags: ::std::option::Option<crate::types::GeneralFlagsV2>,
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    pub extensions: ::std::option::Option<crate::types::ExtensionsV2>,
}
impl TemplateV2 {
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
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, and cryptographic providers for the private key of a certificate for v2 templates. V2 templates allow you to use Legacy Cryptographic Service Providers.</p>
    pub fn private_key_attributes(&self) -> ::std::option::Option<&crate::types::PrivateKeyAttributesV2> {
        self.private_key_attributes.as_ref()
    }
    /// <p>Private key flags for v2 templates specify the client compatibility, if the private key can be exported, and if user input is required when using a private key.</p>
    pub fn private_key_flags(&self) -> ::std::option::Option<&crate::types::PrivateKeyFlagsV2> {
        self.private_key_flags.as_ref()
    }
    /// <p>Enrollment flags describe the enrollment settings for certificates such as using the existing private key and deleting expired or revoked certificates.</p>
    pub fn enrollment_flags(&self) -> ::std::option::Option<&crate::types::EnrollmentFlagsV2> {
        self.enrollment_flags.as_ref()
    }
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    pub fn subject_name_flags(&self) -> ::std::option::Option<&crate::types::SubjectNameFlagsV2> {
        self.subject_name_flags.as_ref()
    }
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    pub fn general_flags(&self) -> ::std::option::Option<&crate::types::GeneralFlagsV2> {
        self.general_flags.as_ref()
    }
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    pub fn extensions(&self) -> ::std::option::Option<&crate::types::ExtensionsV2> {
        self.extensions.as_ref()
    }
}
impl TemplateV2 {
    /// Creates a new builder-style object to manufacture [`TemplateV2`](crate::types::TemplateV2).
    pub fn builder() -> crate::types::builders::TemplateV2Builder {
        crate::types::builders::TemplateV2Builder::default()
    }
}

/// A builder for [`TemplateV2`](crate::types::TemplateV2).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TemplateV2Builder {
    pub(crate) certificate_validity: ::std::option::Option<crate::types::CertificateValidity>,
    pub(crate) superseded_templates: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) private_key_attributes: ::std::option::Option<crate::types::PrivateKeyAttributesV2>,
    pub(crate) private_key_flags: ::std::option::Option<crate::types::PrivateKeyFlagsV2>,
    pub(crate) enrollment_flags: ::std::option::Option<crate::types::EnrollmentFlagsV2>,
    pub(crate) subject_name_flags: ::std::option::Option<crate::types::SubjectNameFlagsV2>,
    pub(crate) general_flags: ::std::option::Option<crate::types::GeneralFlagsV2>,
    pub(crate) extensions: ::std::option::Option<crate::types::ExtensionsV2>,
}
impl TemplateV2Builder {
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
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, and cryptographic providers for the private key of a certificate for v2 templates. V2 templates allow you to use Legacy Cryptographic Service Providers.</p>
    /// This field is required.
    pub fn private_key_attributes(mut self, input: crate::types::PrivateKeyAttributesV2) -> Self {
        self.private_key_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, and cryptographic providers for the private key of a certificate for v2 templates. V2 templates allow you to use Legacy Cryptographic Service Providers.</p>
    pub fn set_private_key_attributes(mut self, input: ::std::option::Option<crate::types::PrivateKeyAttributesV2>) -> Self {
        self.private_key_attributes = input;
        self
    }
    /// <p>Private key attributes allow you to specify the minimal key length, key spec, and cryptographic providers for the private key of a certificate for v2 templates. V2 templates allow you to use Legacy Cryptographic Service Providers.</p>
    pub fn get_private_key_attributes(&self) -> &::std::option::Option<crate::types::PrivateKeyAttributesV2> {
        &self.private_key_attributes
    }
    /// <p>Private key flags for v2 templates specify the client compatibility, if the private key can be exported, and if user input is required when using a private key.</p>
    /// This field is required.
    pub fn private_key_flags(mut self, input: crate::types::PrivateKeyFlagsV2) -> Self {
        self.private_key_flags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Private key flags for v2 templates specify the client compatibility, if the private key can be exported, and if user input is required when using a private key.</p>
    pub fn set_private_key_flags(mut self, input: ::std::option::Option<crate::types::PrivateKeyFlagsV2>) -> Self {
        self.private_key_flags = input;
        self
    }
    /// <p>Private key flags for v2 templates specify the client compatibility, if the private key can be exported, and if user input is required when using a private key.</p>
    pub fn get_private_key_flags(&self) -> &::std::option::Option<crate::types::PrivateKeyFlagsV2> {
        &self.private_key_flags
    }
    /// <p>Enrollment flags describe the enrollment settings for certificates such as using the existing private key and deleting expired or revoked certificates.</p>
    /// This field is required.
    pub fn enrollment_flags(mut self, input: crate::types::EnrollmentFlagsV2) -> Self {
        self.enrollment_flags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enrollment flags describe the enrollment settings for certificates such as using the existing private key and deleting expired or revoked certificates.</p>
    pub fn set_enrollment_flags(mut self, input: ::std::option::Option<crate::types::EnrollmentFlagsV2>) -> Self {
        self.enrollment_flags = input;
        self
    }
    /// <p>Enrollment flags describe the enrollment settings for certificates such as using the existing private key and deleting expired or revoked certificates.</p>
    pub fn get_enrollment_flags(&self) -> &::std::option::Option<crate::types::EnrollmentFlagsV2> {
        &self.enrollment_flags
    }
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    /// This field is required.
    pub fn subject_name_flags(mut self, input: crate::types::SubjectNameFlagsV2) -> Self {
        self.subject_name_flags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    pub fn set_subject_name_flags(mut self, input: ::std::option::Option<crate::types::SubjectNameFlagsV2>) -> Self {
        self.subject_name_flags = input;
        self
    }
    /// <p>Subject name flags describe the subject name and subject alternate name that is included in a certificate.</p>
    pub fn get_subject_name_flags(&self) -> &::std::option::Option<crate::types::SubjectNameFlagsV2> {
        &self.subject_name_flags
    }
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    /// This field is required.
    pub fn general_flags(mut self, input: crate::types::GeneralFlagsV2) -> Self {
        self.general_flags = ::std::option::Option::Some(input);
        self
    }
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    pub fn set_general_flags(mut self, input: ::std::option::Option<crate::types::GeneralFlagsV2>) -> Self {
        self.general_flags = input;
        self
    }
    /// <p>General flags describe whether the template is used for computers or users and if the template can be used with autoenrollment.</p>
    pub fn get_general_flags(&self) -> &::std::option::Option<crate::types::GeneralFlagsV2> {
        &self.general_flags
    }
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    /// This field is required.
    pub fn extensions(mut self, input: crate::types::ExtensionsV2) -> Self {
        self.extensions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    pub fn set_extensions(mut self, input: ::std::option::Option<crate::types::ExtensionsV2>) -> Self {
        self.extensions = input;
        self
    }
    /// <p>Extensions describe the key usage extensions and application policies for a template.</p>
    pub fn get_extensions(&self) -> &::std::option::Option<crate::types::ExtensionsV2> {
        &self.extensions
    }
    /// Consumes the builder and constructs a [`TemplateV2`](crate::types::TemplateV2).
    pub fn build(self) -> crate::types::TemplateV2 {
        crate::types::TemplateV2 {
            certificate_validity: self.certificate_validity,
            superseded_templates: self.superseded_templates,
            private_key_attributes: self.private_key_attributes,
            private_key_flags: self.private_key_flags,
            enrollment_flags: self.enrollment_flags,
            subject_name_flags: self.subject_name_flags,
            general_flags: self.general_flags,
            extensions: self.extensions,
        }
    }
}
