// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchUsersByImageOutput {
    /// <p>An array of UserID objects that matched the input face, along with the confidence in the match. The returned structure will be empty if there are no matches. Returned if the SearchUsersByImageResponse action is successful.</p>
    pub user_matches: ::std::option::Option<::std::vec::Vec<crate::types::UserMatch>>,
    /// <p>Version number of the face detection model associated with the input collection CollectionId.</p>
    pub face_model_version: ::std::option::Option<::std::string::String>,
    /// <p>A list of FaceDetail objects containing the BoundingBox for the largest face in image, as well as the confidence in the bounding box, that was searched for matches. If no valid face is detected in the image the response will contain no SearchedFace object.</p>
    pub searched_face: ::std::option::Option<crate::types::SearchedFaceDetails>,
    /// <p>List of UnsearchedFace objects. Contains the face details infered from the specified image but not used for search. Contains reasons that describe why a face wasn't used for Search.</p>
    pub unsearched_faces: ::std::option::Option<::std::vec::Vec<crate::types::UnsearchedFace>>,
    _request_id: Option<String>,
}
impl SearchUsersByImageOutput {
    /// <p>An array of UserID objects that matched the input face, along with the confidence in the match. The returned structure will be empty if there are no matches. Returned if the SearchUsersByImageResponse action is successful.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_matches.is_none()`.
    pub fn user_matches(&self) -> &[crate::types::UserMatch] {
        self.user_matches.as_deref().unwrap_or_default()
    }
    /// <p>Version number of the face detection model associated with the input collection CollectionId.</p>
    pub fn face_model_version(&self) -> ::std::option::Option<&str> {
        self.face_model_version.as_deref()
    }
    /// <p>A list of FaceDetail objects containing the BoundingBox for the largest face in image, as well as the confidence in the bounding box, that was searched for matches. If no valid face is detected in the image the response will contain no SearchedFace object.</p>
    pub fn searched_face(&self) -> ::std::option::Option<&crate::types::SearchedFaceDetails> {
        self.searched_face.as_ref()
    }
    /// <p>List of UnsearchedFace objects. Contains the face details infered from the specified image but not used for search. Contains reasons that describe why a face wasn't used for Search.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.unsearched_faces.is_none()`.
    pub fn unsearched_faces(&self) -> &[crate::types::UnsearchedFace] {
        self.unsearched_faces.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for SearchUsersByImageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SearchUsersByImageOutput {
    /// Creates a new builder-style object to manufacture [`SearchUsersByImageOutput`](crate::operation::search_users_by_image::SearchUsersByImageOutput).
    pub fn builder() -> crate::operation::search_users_by_image::builders::SearchUsersByImageOutputBuilder {
        crate::operation::search_users_by_image::builders::SearchUsersByImageOutputBuilder::default()
    }
}

/// A builder for [`SearchUsersByImageOutput`](crate::operation::search_users_by_image::SearchUsersByImageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchUsersByImageOutputBuilder {
    pub(crate) user_matches: ::std::option::Option<::std::vec::Vec<crate::types::UserMatch>>,
    pub(crate) face_model_version: ::std::option::Option<::std::string::String>,
    pub(crate) searched_face: ::std::option::Option<crate::types::SearchedFaceDetails>,
    pub(crate) unsearched_faces: ::std::option::Option<::std::vec::Vec<crate::types::UnsearchedFace>>,
    _request_id: Option<String>,
}
impl SearchUsersByImageOutputBuilder {
    /// Appends an item to `user_matches`.
    ///
    /// To override the contents of this collection use [`set_user_matches`](Self::set_user_matches).
    ///
    /// <p>An array of UserID objects that matched the input face, along with the confidence in the match. The returned structure will be empty if there are no matches. Returned if the SearchUsersByImageResponse action is successful.</p>
    pub fn user_matches(mut self, input: crate::types::UserMatch) -> Self {
        let mut v = self.user_matches.unwrap_or_default();
        v.push(input);
        self.user_matches = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of UserID objects that matched the input face, along with the confidence in the match. The returned structure will be empty if there are no matches. Returned if the SearchUsersByImageResponse action is successful.</p>
    pub fn set_user_matches(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserMatch>>) -> Self {
        self.user_matches = input;
        self
    }
    /// <p>An array of UserID objects that matched the input face, along with the confidence in the match. The returned structure will be empty if there are no matches. Returned if the SearchUsersByImageResponse action is successful.</p>
    pub fn get_user_matches(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserMatch>> {
        &self.user_matches
    }
    /// <p>Version number of the face detection model associated with the input collection CollectionId.</p>
    pub fn face_model_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.face_model_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Version number of the face detection model associated with the input collection CollectionId.</p>
    pub fn set_face_model_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.face_model_version = input;
        self
    }
    /// <p>Version number of the face detection model associated with the input collection CollectionId.</p>
    pub fn get_face_model_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.face_model_version
    }
    /// <p>A list of FaceDetail objects containing the BoundingBox for the largest face in image, as well as the confidence in the bounding box, that was searched for matches. If no valid face is detected in the image the response will contain no SearchedFace object.</p>
    pub fn searched_face(mut self, input: crate::types::SearchedFaceDetails) -> Self {
        self.searched_face = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of FaceDetail objects containing the BoundingBox for the largest face in image, as well as the confidence in the bounding box, that was searched for matches. If no valid face is detected in the image the response will contain no SearchedFace object.</p>
    pub fn set_searched_face(mut self, input: ::std::option::Option<crate::types::SearchedFaceDetails>) -> Self {
        self.searched_face = input;
        self
    }
    /// <p>A list of FaceDetail objects containing the BoundingBox for the largest face in image, as well as the confidence in the bounding box, that was searched for matches. If no valid face is detected in the image the response will contain no SearchedFace object.</p>
    pub fn get_searched_face(&self) -> &::std::option::Option<crate::types::SearchedFaceDetails> {
        &self.searched_face
    }
    /// Appends an item to `unsearched_faces`.
    ///
    /// To override the contents of this collection use [`set_unsearched_faces`](Self::set_unsearched_faces).
    ///
    /// <p>List of UnsearchedFace objects. Contains the face details infered from the specified image but not used for search. Contains reasons that describe why a face wasn't used for Search.</p>
    pub fn unsearched_faces(mut self, input: crate::types::UnsearchedFace) -> Self {
        let mut v = self.unsearched_faces.unwrap_or_default();
        v.push(input);
        self.unsearched_faces = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of UnsearchedFace objects. Contains the face details infered from the specified image but not used for search. Contains reasons that describe why a face wasn't used for Search.</p>
    pub fn set_unsearched_faces(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UnsearchedFace>>) -> Self {
        self.unsearched_faces = input;
        self
    }
    /// <p>List of UnsearchedFace objects. Contains the face details infered from the specified image but not used for search. Contains reasons that describe why a face wasn't used for Search.</p>
    pub fn get_unsearched_faces(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UnsearchedFace>> {
        &self.unsearched_faces
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SearchUsersByImageOutput`](crate::operation::search_users_by_image::SearchUsersByImageOutput).
    pub fn build(self) -> crate::operation::search_users_by_image::SearchUsersByImageOutput {
        crate::operation::search_users_by_image::SearchUsersByImageOutput {
            user_matches: self.user_matches,
            face_model_version: self.face_model_version,
            searched_face: self.searched_face,
            unsearched_faces: self.unsearched_faces,
            _request_id: self._request_id,
        }
    }
}
