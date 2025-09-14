#include "include/PcapLib/Lidar2DViewer.h"

Lidar2DViewer::Lidar2DViewer(int width, int height) : windowWidth(width), windowHeight(height),
                                                      windowName("LIDAR 2D Viewer"), isWindowCreated(false) {
    canvas = cv::Mat::zeros(height, width, CV_8UC3);  // Canvas đen 3 kênh (BGR).
    cv::namedWindow(windowName, cv::WINDOW_AUTOSIZE);  // Tạo cửa sổ.
    isWindowCreated = true;
}

Lidar2DViewer::~Lidar2DViewer() {
    close();
}

void Lidar2DViewer::update(const std::vector<cv::Point2f>& lidarPoints, const cv::Scalar& pointColor, int pointSize) {
     //canvas = cv::Scalar(0, 0, 0);  // Xóa canvas về đen.
    for (const auto& point : lidarPoints) {
        cv::circle(canvas, point, pointSize/2, pointColor, -1);  // Vẽ điểm đầy.
    }
}
void Lidar2DViewer::clear_all_pixel() {
    canvas = cv::Scalar(0, 0, 0);
}

void Lidar2DViewer::show() {
    if (isWindowCreated) {
        cv::imshow(windowName, canvas);
    }
}

void Lidar2DViewer::close() {
    if (isWindowCreated) {
        cv::destroyWindow(windowName);
        isWindowCreated = false;
    }
}