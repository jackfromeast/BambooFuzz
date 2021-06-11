import os
from flask_uploads import UploadSet, configure_uploads, ARCHIVES
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import TextField, PasswordField
from wtforms.validators import InputRequired, DataRequired
from wtforms import SubmitField
# from Web.run import firmware
# 这里要和run.py里的内容保持一致，因为不知道怎么从外面引进来所以只好搞两个firmware
archives=list(ARCHIVES)
archives.append("bin")
archives.append("")
firmware = UploadSet('firmware', ARCHIVES)


class UploadForm(FlaskForm):
    firmware = FileField(validators=[
        FileAllowed(firmware, u'只能上传bin文件或压缩文件！'), 
        FileRequired(u'文件未选择！')])
    name = TextField('firmwareName1', id='firmwareName1', validators=[DataRequired()])
    # brand = TextField('brandSelect1', id='brandSelect1', validators=[DataRequired()])
    info = TextField('info1', id='info1', validators=[DataRequired()])
    submit = SubmitField(u'提交')


