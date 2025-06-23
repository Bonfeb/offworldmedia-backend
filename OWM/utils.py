from cloudinary_storage.storage import MediaCloudinaryStorage

class VideoMediaCloudinaryStorage(MediaCloudinaryStorage):
    def get_options(self, name):
        options = super().get_options(name)
        options['resource_type'] = 'video'
        return options

